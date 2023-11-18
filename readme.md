# Kubernetes Secret Vault

This is a simple Kubernetes Secret Vault implemented in Go, utilizing the [chi](https://github.com/go-chi/chi) router and the Kubernetes client library.

## Overview

The Secret Vault provides a REST API for managing secrets stored in Kubernetes secrets. It includes functionalities such as creating namespaces, generating and validating secret codes for authentication, storing, updating, and deleting secrets.

## Getting Started

### Prerequisites

- Go installed on your machine.
- Kubernetes cluster access with `kubectl` configured.
- Set up a Kubernetes cluster with the required RBAC permissions.

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/AshvinViknes/kubernetes-secret-vault.git
   ```

2. Navigate to the project directory:

   ```bash
   cd kubernetes-secret-vault
   ```

3. Run the application:

   ```bash
   go run server.go
   ```

   The server will start running on `http://localhost:6000`.

## API Endpoints

### 1. Create Kubernetes Namespace

- **Endpoint:** `/namespace`
- **Method:** `POST`
- **Request Body:**

  ```json
  {
    "namespace": "example-namespace"
  }
  ```

### 2. User Login and Secret Code Generation

- **Endpoint:** `/login`
- **Method:** `POST`
- **Request Body:**

  ```json
  {
    "user_id": "user123",
    "password": "password123"
  }
  ```

  **Response:**

  ```json
  {
    "secretCode": "generated-secret-code"
  }
  ```

### 3. Get Secret

- **Endpoint:** `/secret/{secretName}`
- **Method:** `GET`
- **Request Header:**

  ```
  secret-code: generated-secret-code
  ```

  **Response:**

  ```json
  {
    "secretData": {
      "secretKey1": "secretValue1",
      "secretKey2": "secretValue2"
    },
    "message": "Secret data retrieved successfully"
  }
  ```

### 4. Store Secret

- **Endpoint:** `/secret`
- **Method:** `POST`
- **Request Header:**

  ```
  secret-code: generated-secret-code
  ```

- **Request Body:**

  ```json
  {
    "secretName": "example-secret",
    "secretData": [
      {
        "secretKey": "key1",
        "secretValue": "value1"
      },
      {
        "secretKey": "key2",
        "secretValue": "value2"
      }
    ]
  }
  ```

  **Response:**

  ```json
  {
    "message": "Secret data stored successfully"
  }
  ```

### 5. Update Secret

- **Endpoint:** `/secret`
- **Method:** `PUT`
- **Request Header:**

  ```
  secret-code: generated-secret-code
  ```

- **Request Body:**

  ```json
  {
    "secretName": "example-secret",
    "secretData": [
      {
        "secretKey": "key1",
        "secretValue": "new-value1"
      }
    ]
  }
  ```

  **Response:**

  ```json
  {
    "message": "Secret data updated successfully"
  }
  ```

### 6. Delete Secret Keys

- **Endpoint:** `/secret`
- **Method:** `DELETE`
- **Request Header:**

  ```
  secret-code: generated-secret-code
  ```

- **Request Body:**

  ```json
  [
    {
      "secretName": "example-secret",
      "secretKeysToDelete": ["key1"]
    }
  ]
  ```

  **Response:**

  ```json
  {
    "message": "Keys deleted successfully from secrets"
  }
  ```

## Note

- The secrets are stored in the Kubernetes cluster, and the namespace is specified in the `VAULT` environment variable.