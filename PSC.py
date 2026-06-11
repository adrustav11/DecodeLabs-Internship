def check_password_strength(password):

    length = len(password) >= 8
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_symbol = any(not char.isalnum() for char in password)

    if length and has_upper and has_lower and has_digit and has_symbol:
        return "Strong 🟢"

    elif length and (has_digit or has_upper):
        return "Medium 🟠"

    else:
        return "Weak 🔴"


password = input("Enter a password: ")

strength = check_password_strength(password)

print("\nPassword Strength:", strength)

print("\nPassword Analysis:")
print("Length >= 8:", len(password) >= 8)
print("Contains Uppercase:", any(char.isupper() for char in password))
print("Contains Lowercase:", any(char.islower() for char in password))
print("Contains Number:", any(char.isdigit() for char in password))
print("Contains Special Symbol:", any(not char.isalnum() for char in password))
 