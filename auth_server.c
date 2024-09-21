#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/sha.h>

#define MAX_USERNAME 50
#define MAX_PASSWORD 50
#define CREDENTIALS_FILE "credentials.txt"

// Function to hash a password using SHA-256
void hash_password(const char* password, char* outputBuffer) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password, strlen(password));
    SHA256_Final(hash, &sha256);
    
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = 0;  // Null-terminate the hash
}

// Function to check if the password is valid
int validate_password(const char* password) {
    int has_letter = 0, has_digit = 0;
    if(strlen(password) < 8) return 0;  // Password too short
    for(int i = 0; password[i]; i++) {
        if(isalpha(password[i])) has_letter = 1;
        if(isdigit(password[i])) has_digit = 1;
    }
    return has_letter && has_digit;  // Must contain at least one letter and one digit
}

// Check if username exists in the credentials file
int user_exists(const char* username) {
    FILE *file = fopen(CREDENTIALS_FILE, "r");
    if (!file) return 0;
    char stored_username[MAX_USERNAME];
    
    while (fscanf(file, "%s", stored_username) != EOF) {
        if (strcmp(username, stored_username) == 0) {
            fclose(file);
            return 1;  // Username found
        }
        fseek(file, 65, SEEK_CUR);  // Skip the stored hash
    }
    
    fclose(file);
    return 0;
}

// Register a new user by storing username and hashed password
void register_user() {
    char username[MAX_USERNAME], password[MAX_PASSWORD], hashed_password[65];
    
    printf("Enter username: ");
    scanf("%s", username);
    
    if (strlen(username) == 0) {
        printf("Username cannot be empty.\n");
        return;
    }

    if (user_exists(username)) {
        printf("Username already exists.\n");
        return;
    }
    
    printf("Enter password (at least 8 characters, with one letter and one number): ");
    scanf("%s", password);
    
    if (!validate_password(password)) {
        printf("Invalid password. Must be at least 8 characters long, contain a letter and a number.\n");
        return;
    }
    
    // Hash the password
    hash_password(password, hashed_password);
    
    // Store the credentials
    FILE *file = fopen(CREDENTIALS_FILE, "a");
    if (file) {
        fprintf(file, "%s %s\n", username, hashed_password);
        fclose(file);
        printf("User registered successfully!\n");
    } else {
        printf("Error opening file for writing.\n");
    }
}

// Check if login credentials are valid
void login() {
    // Sample Account
    // Username: walter.parker
    // Password: gh05t_1n_4_5h311c0d3
    char username[MAX_USERNAME], password[MAX_PASSWORD], stored_username[MAX_USERNAME], stored_hashed_password[65], hashed_password[65];
    
    printf("Enter username: ");
    scanf("%s", username);
    
    printf("Enter password: ");
    scanf("%s", password);
    
    // Hash the input password
    hash_password(password, hashed_password);
    
    // Check the credentials file for the username and hash
    FILE *file = fopen(CREDENTIALS_FILE, "r");
    if (!file) {
        printf("Error opening credentials file.\n");
        return;
    }
    
    int found = 0;
    while (fscanf(file, "%s %s", stored_username, stored_hashed_password) != EOF) {
        if (strcmp(username, stored_username) == 0 && strcmp(hashed_password, stored_hashed_password) == 0) {
            found = 1;
            break;
        }
    }
    
    fclose(file);
    
    if (found) {
        printf("Login successful!\n");
        char logout_choice;
        printf("Do you want to logout? (y/n): ");
        scanf(" %c", &logout_choice);
        if (logout_choice == 'y' || logout_choice == 'Y') {
            printf("Logged out successfully.\n");
        }
    } else {
        printf("Invalid username or password.\n");
    }
}

int main() {
    int choice;
    
    while (1) {
        printf("\n--- DeltaEgrep Security Authentication ---\n");
        printf("1. Register\n");
        printf("2. Login\n");
        printf("3. Exit\n");
        printf("Choose an option: ");
        scanf("%d", &choice);
        
        switch (choice) {
            case 1:
                register_user();
                break;
            case 2:
                login();
                break;
            case 3:
                printf("Exiting...\n");
                exit(0);
                break;
            default:
                printf("Invalid choice. Please try again.\n");
        }
    }
    
    return 0;
}

