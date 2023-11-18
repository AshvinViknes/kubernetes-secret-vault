package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

var secretDatabase []Secret

type Secret struct {
	Code      string
	Used      bool
	UserID    string
	Timestamp time.Time
}

type SecretRequest struct {
	SecretName string       `json:"secretName"`
	SecretData []SecretData `json:"secretData"`
}

type SecretData struct {
	SecretKey   string `json:"secretKey"`
	SecretValue string `json:"secretValue"`
}

type SecretDeleteRequest struct {
	SecretName         string   `json:"secretName"`
	SecretKeysToDelete []string `json:"secretKeysToDelete"`
}

func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Post("/login", LoginHandler)
	r.Post("/namespace", CreateKubernetesNamespace)
	r.With(ValidateSecretCodeMiddleware).Get("/secret/{secretName}", GetSecretHandler)
	r.With(ValidateSecretCodeMiddleware).Post("/secret", StoreSecretHandler)
	r.With(ValidateSecretCodeMiddleware).Put("/secret", UpdateSecretHandler)
	r.With(ValidateSecretCodeMiddleware).Delete("/secret", DeleteSecretHandler)
	log.Println("Kubernetes Secret Vault")
	http.ListenAndServe(":6000", r)

}
func CreateKubernetesNamespace(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var requestData map[string]string
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	namespace, ok := requestData["namespace"]
	if !ok {
		http.Error(w, "Namespace required", http.StatusBadRequest)
		return
	}
	kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		config, err = rest.InClusterConfig()
		if err != nil {
			fmt.Printf("Error building kubeconfig: %v\n", err)
			http.Error(w, "Error building kubeconfig:"+err.Error(), http.StatusBadRequest)
			return
		}
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		fmt.Printf("Error creating Kubernetes client: %v\n", err)
		http.Error(w, "Error creating Kubernetes client:"+err.Error(), http.StatusBadRequest)
		return
	}
	// Create the namespace
	_, err = clientset.CoreV1().Namespaces().Create(context.TODO(), &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		fmt.Printf("Error creating namespace: %v\n", err)
		http.Error(w, "Error creating namespace:"+err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"namespace": namespace,
		"message":   "Namespace created successfully",
	})
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var requestData map[string]string
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	userID, okUserID := requestData["user_id"]
	_, okPassword := requestData["password"]
	if !okUserID || !okPassword {
		http.Error(w, "User ID and password are required", http.StatusBadRequest)
		return
	}
	// Generate a random secret code
	randomBytes := make([]byte, 8)
	_, err := rand.Read(randomBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error generating random secret code: %v", err), http.StatusInternalServerError)
		return
	}
	secretCode := hex.EncodeToString(randomBytes)
	timestamp := time.Now()
	// Store the generated secret code and timestamp as unused in the in-memory database
	secretDatabase = append(secretDatabase, Secret{Code: secretCode, Used: false, UserID: userID, Timestamp: timestamp})
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"secretCode": secretCode,
	})
}

func ValidateSecretCodeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		providedSecretCode := r.Header.Get("secret-code")
		for i, secret := range secretDatabase {
			if secret.Code == providedSecretCode && !secret.Used {
				// Check if the code is still within the active duration (30 seconds in this example)
				if time.Since(secret.Timestamp) <= 20*time.Second {
					// Mark the code as used
					secretDatabase[i].Used = true
					next.ServeHTTP(w, r)
					return
				} else {
					// Remove expired codes from the database
					secretDatabase = append(secretDatabase[:i], secretDatabase[i+1:]...)
					http.Error(w, "Secret code has expired", http.StatusForbidden)
					return
				}
			}
		}
		http.Error(w, "Invalid secret code", http.StatusForbidden)
	})
}

func GetSecretHandler(w http.ResponseWriter, r *http.Request) {
	secretName := chi.URLParam(r, "secretName")
	secretData, err := GetSecretData(secretName)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"secretData": secretData,
		"message":    "Secret data retrieved successfully",
	})
}

func StoreSecretHandler(w http.ResponseWriter, r *http.Request) {
	var requestData SecretRequest
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if requestData.SecretName == "" {
		http.Error(w, "Secret name is required", http.StatusBadRequest)
		return
	}
	err := StoreSecretData(requestData.SecretName, requestData.SecretData)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error storing secret data: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Secret data stored successfully",
	})
}

func UpdateSecretHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var requestData SecretRequest
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	secretName := requestData.SecretName
	if secretName == "" {
		http.Error(w, "Secret name is required", http.StatusBadRequest)
		return
	}
	err := UpdateSecretData(secretName, requestData.SecretData)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error storing secret data: %v", err), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Secret data updated successfully",
	})
}
func DeleteSecretHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var requestData []SecretDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	for _, request := range requestData {
		if len(request.SecretKeysToDelete) == 0 {
			http.Error(w, fmt.Sprintf("Keys to delete are required for secret %s", request.SecretName), http.StatusBadRequest)
			return
		}
		// Delete the keys within the secret
		err := DeleteSecretKeys(request.SecretName, request.SecretKeysToDelete)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error deleting keys from secret %s: %v", request.SecretName, err), http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Keys deleted successfully from secrets",
	})
}

func GetSecretData(secretName string) (map[string][]byte, error) {
	kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("error building kubeconfig: %v", err)
		}
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error creating Kubernetes client: %v", err)
	}
	namespace, ok := os.LookupEnv("VAULT")
	if !ok {
		return nil, fmt.Errorf("VAULT is not set in ENV")
	}
	// Retrieve the secret
	secret, err := clientset.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error getting secret: %v", err)
	}
	return secret.Data, nil
}

func StoreSecretData(secretName string, data []SecretData) error {
	kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		config, err = rest.InClusterConfig()
		if err != nil {
			return fmt.Errorf("error building kubeconfig: %v", err)
		}
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("error creating Kubernetes client: %v", err)
	}
	namespace, ok := os.LookupEnv("VAULT")
	if !ok {
		return fmt.Errorf("VAULT is not set in ENV")
	}
	_, err = clientset.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
	if err != nil {
		// Hash and update keys in the secret
		secretData := make(map[string][]byte)
		for _, sd := range data {
			hash := sha256.New()
			hash.Write([]byte(sd.SecretValue))
			hashInBytes := hash.Sum(nil)
			hashedValue := hex.EncodeToString(hashInBytes)
			secretData[sd.SecretKey] = []byte(hashedValue)
		}
		// Create the secret in the namespace
		_, err = clientset.CoreV1().Secrets(namespace).Create(context.TODO(), &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName}, Data: secretData}, metav1.CreateOptions{})
		if err != nil {
			fmt.Printf("Error creating secret: %v\n", err)
			return fmt.Errorf("error creating secret: %v", err)
		}
	} else {
		return fmt.Errorf("secretName already exists: %v", secretName)
	}
	return nil
}

func UpdateSecretData(secretName string, data []SecretData) error {
	kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		config, err = rest.InClusterConfig()
		if err != nil {
			return fmt.Errorf("error building kubeconfig: %v", err)
		}
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("error creating Kubernetes client: %v", err)
	}
	namespace, ok := os.LookupEnv("VAULT")
	if !ok {
		return fmt.Errorf("VAULT is not set in ENV")
	}
	// Retrieve the secret
	secret, err := clientset.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting secret: %v", err)
	}
	// Hash and update keys in the secret
	for _, secretData := range data {
		hash := sha256.New()
		hash.Write([]byte(secretData.SecretValue))
		hashInBytes := hash.Sum(nil)
		hashedValue := hex.EncodeToString(hashInBytes)
		secret.Data[secretData.SecretKey] = []byte(hashedValue)
	}
	// Update the secret
	_, err = clientset.CoreV1().Secrets(namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating secret: %v", err)
	}
	return nil
}

func DeleteSecretKeys(secretName string, keys []string) error {
	kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		config, err = rest.InClusterConfig()
		if err != nil {
			return fmt.Errorf("error building kubeconfig: %v", err)
		}
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("error creating Kubernetes client: %v", err)
	}
	namespace, ok := os.LookupEnv("VAULT")
	if !ok {
		return fmt.Errorf("VAULT is not set in ENV")
	}
	// Retrieve the existing secret
	secret, err := clientset.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting secret: %v", err)
	}
	// Delete specified keys from the secret
	for _, key := range keys {
		delete(secret.Data, key)
	}
	// Update the secret in Kubernetes to apply the changes
	_, err = clientset.CoreV1().Secrets(namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating secret: %v", err)
	}
	return nil
}
