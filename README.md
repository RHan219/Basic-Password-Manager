This is a somewhat basic implementation of a password manager.

To use it, you enter a passkey into the prompt. If no file with this passkey exists, then a new file for that passkey will be created.

When using, you will have 3 options:

1. "a"
   
   This will allow you to enter a label on the password.
   For example, if it a password for hotmail, you could make the label "hotmail".
   After the label, you will input the password, which is then stored in the file after being encrypted in base 64.

3. "r"

   This will allow you to enter a label for one of your existing passwords.
   The program will look for the encrypted password with this label, and then return the password to you after decrypting it.

5. "q"
   
   This will terminate the program.
