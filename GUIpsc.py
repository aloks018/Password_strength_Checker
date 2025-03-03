import customtkinter as ctk
import re
import secrets
import string
import webbrowser
import datetime

# Initialize CustomTkinter appearance
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")


def check_password_strength(password):
    """
    Evaluates the strength of the password with a more lenient approach.
    """
    strength_score = 0
    strength_desc = "Weak"
    color = "red"

    # Lenient criteria
    if len(password) >= 6:  # Reduce minimum length to 6
        strength_score += 1
    if re.search(r"[A-Z]", password):  # Bonus for uppercase letters
        strength_score += 1
    if re.search(r"[a-z]", password):  # Bonus for lowercase letters
        strength_score += 1
    if re.search(r"\d", password):  # Bonus for digits
        strength_score += 1
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):  # Bonus for special characters
        strength_score += 1

    # Adjusted thresholds
    if strength_score == 1:
        strength_desc = "Very Weak"
        color = "red"
    elif 2 <= strength_score <= 3:
        strength_desc = "Weak"
        color = "orange"
    elif 4 <= strength_score:
        strength_desc = "Moderate"
        color = "yellow"
    if len(password) >= 8 and strength_score >= 4:  # Strong passwords require good length + variety
        strength_desc = "Strong"
        color = "green"

    return strength_desc, color


def generate_username_based_passwords(username):
    """
    Suggests passwords based on the entered username with variations for security.
    """
    suggestions = []
    special_chars = "!@#$%^&*"
    for _ in range(5):
        part = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(6))
        suggestion = (
            secrets.choice(special_chars)  # Start with a special character
            + part  # Add a random alphanumeric sequence
            + secrets.choice(special_chars)  # Add another special character
        )
        suggestions.append(suggestion)
    return suggestions


def generate_strong_password():
    """
    Generates a strong password with at least one uppercase letter, one lowercase letter,
    one digit, and one special character.
    """
    characters = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(characters) for _ in range(12))
        if (any(c.islower() for c in password) and
                any(c.isupper() for c in password) and
                any(c.isdigit() for c in password) and
                any(c in string.punctuation for c in password)):
            return password


def validate_dob():
    """
    Validates the Date of Birth entry field format.
    """
    dob = dob_entry.get()
    try:
        datetime.datetime.strptime(dob, "%d/%m/%Y")
        dob_label.configure(text="Date of Birth is valid", text_color="green")
    except ValueError:
        dob_label.configure(text="Invalid Date of Birth format!", text_color="red")


import tkinter.messagebox as messagebox

def evaluate_password():
    """
    Evaluates the password entered in the input field and updates the strength label.
    """
    password = password_entry.get()
    strength, color = check_password_strength(password)

    # Update strength label
    if strength == "Weak":
        strength_label.configure(
            text="Strength: Weak - Use at least 8 characters, mix cases, numbers, and symbols.", text_color=color)
    elif strength == "Moderate":
        strength_label.configure(
            text="Strength: Moderate - Try adding more symbols and numbers.", text_color=color)
    elif strength == "Strong":
        strength_label.configure(text="Strength: Strong - Great password!", text_color=color)
        # Show a message box instead of linking to a website
        messagebox.showinfo("Password Strength", "Congratulations! You are safe!")


def show_suggestions():
    """
    Displays strong password suggestions in the text box.
    """
    username = username_entry.get()
    if username:
        suggestions = "\n".join(generate_username_based_passwords(username))
    else:
        suggestions = "\n".join([generate_strong_password() for _ in range(3)])
    suggestion_box.configure(state="normal")
    suggestion_box.delete("1.0", ctk.END)
    suggestion_box.insert(ctk.END, suggestions)
    suggestion_box.configure(state="disabled")


def reset_suggestion_button():
    """
    Resets the suggestion button text.
    """
    suggestion_button.configure(text="✨ Suggest Passwords")


def copy_to_clipboard():
    """
    Copies the content of the suggestion box to the clipboard.
    """
    app.clipboard_clear()
    app.clipboard_append(suggestion_box.get("1.0", ctk.END).strip())
    app.update()
    suggestion_button.configure(text="Copied!")
    app.after(2000, reset_suggestion_button)  # Reset after 2 seconds


def toggle_password_visibility():
    """
    Toggles the visibility of the password entry field.
    """
    if password_entry.cget("show") == "*":
        password_entry.configure(show="")
        toggle_button.configure(text="🙈 Hide")
    else:
        password_entry.configure(show="*")
        toggle_button.configure(text="👁 Show")


# Main application window
app = ctk.CTk()
app.title("Password Strength Checker")
app.geometry("600x700")

# Background frame
background_frame = ctk.CTkFrame(app, fg_color="#18aaff")
background_frame.pack(fill="both", expand=True, padx=20, pady=20)

# Title label
title_label = ctk.CTkLabel(background_frame, text="🔐 Password Strength Checker", font=("Arial", 24, "bold"),
                           text_color="#F74589")
title_label.pack(pady=20)

# Username entry field
username_label = ctk.CTkLabel(background_frame, text="Enter your username:", font=("Arial", 14, "bold"),
                              text_color="#ffffff")
username_label.pack(pady=5)
username_entry = ctk.CTkEntry(background_frame, placeholder_text="Enter your username", width=300, height=35,
                              border_width=2, corner_radius=10)
username_entry.pack(pady=10)

# Date of Birth entry field
dob_label = ctk.CTkLabel(background_frame, text="Enter your Date of Birth (DD/MM/YYYY):", font=("Arial", 14, "bold"),
                         text_color="dark green")
dob_label.pack(pady=5)
dob_entry = ctk.CTkEntry(background_frame, placeholder_text="DD/MM/YYYY", width=300, height=35, border_width=2,
                         corner_radius=10, fg_color="#145A32", text_color="white")
dob_entry.pack(pady=10)
dob_validate_button = ctk.CTkButton(background_frame, text="Validate DOB", command=validate_dob, fg_color="#58D68D",
                                    font=("Arial", 12))
dob_validate_button.pack(pady=5)

# Password entry field
password_label = ctk.CTkLabel(background_frame, text="Enter your password:", font=("Arial", 14, "bold"),
                              text_color="#ffffff")
password_label.pack(pady=5)
password_entry = ctk.CTkEntry(background_frame, placeholder_text="Enter your password", show="*", width=300,
                              height=35, border_width=2, corner_radius=10)
password_entry.pack(pady=10)

# Toggle visibility button
toggle_button = ctk.CTkButton(background_frame, text="👁 Show", command=toggle_password_visibility,
                              fg_color="#D35400", hover_color="#E67E22", font=("Arial", 12))
toggle_button.pack(pady=5)

# Strength display label
strength_label = ctk.CTkLabel(background_frame, text="Strength: ", font=("Arial", 18, "bold"), text_color="#ffffff")
strength_label.pack(pady=10)

# Check strength button
check_button = ctk.CTkButton(background_frame, text="🔍 Check Strength", command=evaluate_password,
                             fg_color="#58D68D", hover_color="#45B39D", font=("Arial", 14, "bold"))
check_button.pack(pady=10)

# Generate suggestions button
suggestion_button = ctk.CTkButton(background_frame, text="✨ Suggest Passwords", command=show_suggestions,
                                   fg_color="#018efe", hover_color="#5DADE2", font=("Arial", 14, "bold"))
suggestion_button.pack(pady=10)

# Copy to clipboard button
copy_button = ctk.CTkButton(background_frame, text="📋 Copy Suggestions", command=copy_to_clipboard,
                            fg_color="#F4D03F", hover_color="#F5B041", font=("Arial", 14, "bold"))
copy_button.pack(pady=10)

# Suggestion box with scrollbar
suggestion_box = ctk.CTkTextbox(background_frame, width=400, height=120, border_width=2, corner_radius=10,
                                fg_color="#1C2833", text_color="#589d34", wrap="word")
scrollbar = ctk.CTkScrollbar(background_frame, command=suggestion_box.yview)
suggestion_box.configure(yscrollcommand=scrollbar.set)
suggestion_box.pack(side="left", pady=10)
scrollbar.pack(side="right", fill="y")

suggestion_box.insert(ctk.END, "Click 'Suggest Passwords' for ideas.")
suggestion_box.configure(state="disabled")

# Run the application
app.mainloop()
