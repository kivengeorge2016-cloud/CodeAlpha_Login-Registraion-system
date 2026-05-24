#ifndef AUTH_H
#define AUTH_H

#include <iostream>
#include <string>
using namespace std;

// Hashes a password using a simple XOR + shift method
string hashPassword(const string& password);

// Validates username and password meet requirements
bool validateInput(const string& username, const string& password);

// Checks if a username already exists in the database file
bool userExists(const string& username);

// Registers a new user; returns true on success
bool registerUser(const string& username, const string& password);

// Logs in an existing user; returns true on success
bool loginUser(const string& username, const string& password);

// Displays the main menu and returns the user's choice
int showMenu();

#endif
