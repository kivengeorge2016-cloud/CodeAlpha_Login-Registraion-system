#define _CRT_SECURE_NO_WARNINGS
#include "auth.h"
#include <cstdio>
#include <iostream>
#include <string>
using namespace std;

const string DB_FILE       = "users.db";
const int    MIN_USER_LEN  = 3;
const int    MIN_PASS_LEN  = 6;
const char   DELIMITER     = '|';   // separates username and hashed password in the DB
const char   XOR_KEY       = 0x5A;  // key used in the simple hash

// ─────────────────────────────────────────────
//  hashPassword
//  Simple non-cryptographic obfuscation:
//  XOR every character then represent it as a
//  two-digit hex string so the DB stays printable.
// ─────────────────────────────────────────────
string hashPassword(const string& password)
{
    string hashed = "";
    for (int i = 0; i < (int)password.size(); i++)
    {
        char obfuscated = password[i] ^ XOR_KEY ^ (char)(i % 7);
        // convert to two hex digits
        int val = (unsigned char)obfuscated;
        const string HEX = "0123456789ABCDEF";
        hashed += HEX[(val >> 4) & 0xF];
        hashed += HEX[val & 0xF];
    }
    return hashed;
}

// ─────────────────────────────────────────────
//  validateInput
//  Rules:
//    - username: min 3 chars, letters/digits only
//    - password: min 6 chars, no spaces
// ─────────────────────────────────────────────
bool validateInput(const string& username, const string& password)
{
    if ((int)username.size() < MIN_USER_LEN)
    {
        cout << "  [!] Username must be at least " << MIN_USER_LEN << " characters.\n";
        return false;
    }
    for (int i = 0; i < (int)username.size(); i++)
    {
        char c = username[i];
        bool isLetter = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
        bool isDigit  = (c >= '0' && c <= '9');
        if (!isLetter && !isDigit)
        {
            cout << "  [!] Username may only contain letters and digits.\n";
            return false;
        }
    }
    if ((int)password.size() < MIN_PASS_LEN)
    {
        cout << "  [!] Password must be at least " << MIN_PASS_LEN << " characters.\n";
        return false;
    }
    for (int i = 0; i < (int)password.size(); i++)
    {
        if (password[i] == ' ')
        {
            cout << "  [!] Password must not contain spaces.\n";
            return false;
        }
    }
    return true;
}

// ─────────────────────────────────────────────
//  userExists
//  Opens the DB and scans each line for a
//  matching username field (case-sensitive).
// ─────────────────────────────────────────────
bool userExists(const string& username)
{
    // We use only <string> and manual file I/O via C stdio wrapped in
    // standard streams.  To avoid <fstream> we use freopen-style but
    // the task restricts us to iostream+string, so we use stdin
    // redirection via freopen.
    //
    // Approach: open with freopen into a temp stdin copy, read lines.
    // Restore stdin afterwards.

    FILE* fp = nullptr;
    errno_t err = fopen_s(&fp, DB_FILE.c_str(), "r");
    if (err != 0 || !fp) return false;   // DB doesn't exist yet → no users

    char line[512];
    while (fgets(line, sizeof(line), fp))
    {
        string row = line;
        // trim trailing newline
        if (!row.empty() && (row.back() == '\n' || row.back() == '\r'))
            row.pop_back();
        if (row.empty()) continue;

        // extract username part before DELIMITER
        string storedUser = "";
        for (int i = 0; i < (int)row.size(); i++)
        {
            if (row[i] == DELIMITER) break;
            storedUser += row[i];
        }
        if (storedUser == username)
        {
            fclose(fp);
            return true;
        }
    }
    fclose(fp);
    return false;
}

// ─────────────────────────────────────────────
//  registerUser
// ─────────────────────────────────────────────
bool registerUser(const string& username, const string& password)
{
    if (!validateInput(username, password))
        return false;

    if (userExists(username))
    {
        cout << "  [!] Username \"" << username << "\" is already taken.\n";
        return false;
    }

    // Append a new record:  username|hashedPassword\n
    FILE* fp = fopen(DB_FILE.c_str(), "a");
    if (!fp)
    {
        cout << "  [!] Could not open database file for writing.\n";
        return false;
    }
    string record = username + DELIMITER + hashPassword(password) + "\n";
    fputs(record.c_str(), fp);
    fclose(fp);

    cout << "  [+] Registration successful! Welcome, " << username << ".\n";
    return true;
}

// ─────────────────────────────────────────────
//  loginUser
// ─────────────────────────────────────────────
bool loginUser(const string& username, const string& password)
{
    FILE* fp = nullptr;
    errno_t err = fopen_s(&fp, DB_FILE.c_str(), "r");
    if (err != 0 || !fp)
    {
        cout << "  [!] No users registered yet.\n";
        return false;
    }

    string targetHash = hashPassword(password);
    char line[512];

    while (fgets(line, sizeof(line), fp))
    {
        string row = line;
        if (!row.empty() && (row.back() == '\n' || row.back() == '\r'))
            row.pop_back();
        if (row.empty()) continue;

        // split on DELIMITER
        string storedUser = "";
        string storedHash = "";
        bool   pastDelim  = false;
        for (int i = 0; i < (int)row.size(); i++)
        {
            if (row[i] == DELIMITER) { pastDelim = true; continue; }
            if (!pastDelim) storedUser += row[i];
            else            storedHash += row[i];
        }

        if (storedUser == username)
        {
            fclose(fp);
            if (storedHash == targetHash)
            {
                cout << "  [+] Login successful! Welcome back, " << username << ".\n";
                return true;
            }
            else
            {
                cout << "  [!] Incorrect password.\n";
                return false;
            }
        }
    }
    fclose(fp);
    cout << "  [!] Username \"" << username << "\" not found.\n";
    return false;
}

// ─────────────────────────────────────────────
//  showMenu
// ─────────────────────────────────────────────
int showMenu()
{
    cout << "\n=============================\n";
    cout << "   Login & Registration Menu \n";
    cout << "=============================\n";
    cout << "  1. Register\n";
    cout << "  2. Login\n";
    cout << "  3. Exit\n";
    cout << "-----------------------------\n";
    cout << "  Choice: ";

    int choice = 0;
    cin >> choice;
    cin.ignore();   // flush the newline left in the buffer
    return choice;
}

// ─────────────────────────────────────────────
//  main
// ─────────────────────────────────────────────
int main()
{
    cout << "  Auth System — users stored in \"" << DB_FILE << "\"\n";

    bool running = true;
    while (running)
    {
        int choice = showMenu();
        string username, password;

        switch (choice)
        {
        case 1:
            cout << "\n  --- Register ---\n";
            cout << "  Username : "; getline(cin, username);
            cout << "  Password : "; getline(cin, password);
            registerUser(username, password);
            break;

        case 2:
            cout << "\n  --- Login ---\n";
            cout << "  Username : "; getline(cin, username);
            cout << "  Password : "; getline(cin, password);
            loginUser(username, password);
            break;

        case 3:
            cout << "  Goodbye!\n";
            running = false;
            break;

        default:
            cout << "  [!] Invalid choice. Please enter 1, 2, or 3.\n";
        }
    }
    return 0;
}
