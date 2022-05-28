import string

# Weak protections that remove certain inputs
#reactive security 
def weakProtection(input):
    removal_list = ["'",";", "-"]

    for word in removal_list:
        input = input.replace(word, "")
    return input

# Strong protection that only allows certain inputs
#proactive security 
def strongProtection(input):
    # Create a whitelist that only allows certain characters
    whitelist = set(string.digits + string.ascii_lowercase + string.ascii_uppercase + "#" + "_" + "[" + "]" + "!" + "@" + "$" + "^" + "%" + "*" + "(" + ")" + ")" + "{" + "}")
    safe =""
    for i in range(len(input)):
        if input[i] in whitelist:
            safe += input[i]
    return safe
    
# Receives username and password, runs them against different protection scenarios, and calls the output function to format them for output the to screen   
def output(user, password):
    print("")
    print("No Protection:")
    print(sqlstring(user, password))
    print("Weak Protection:")
    print(sqlstring(weakProtection(user), weakProtection(password)))
    print("Strong Protection:")
    print(sqlstring(strongProtection(user), strongProtection(password)))

  
# Formatting output to the screen
def sqlstring(user, password):
    # String value that is used as part of a Union attack
    union = "' UNION"
    # String value that is used as part of a comment attack
    comment = "; --"
    # Outputting a SQL statement based on the nature of the attacker's code
    #This if selection covers the Union attack
    if union in password:
        return(f"SELECT *\n     FROM register\n     WHERE username='{user}' and password='{password};\n")
    #This elif selection covers the comment attack 
    elif comment in user:
        return(f"SELECT *\n     FROM register\n     WHERE username='{user} and password='{password}';\n")
    #This else covers the valid username and password and covers the Tautology attacks and  Add Statment
    else:
        return(f"SELECT *\n     FROM register\n     WHERE username='{user}' and password='{password}';\n")

# Tests that are run to show valid inputs    
def valid_tests():
    # Ryan's Test Cases
    print("Ryan's Cases")
  
    print("VLDT-1-A")
    output("ryaN23214", "Test_1234")
  
    print("VLDT-1-B")
    output("RyanT", "Password_1234")
  
    print("VLDT-1-C")
    output("rTaniguchi", "BYU_I1")
  
    # Ian's Test Cases
    print("Ian's Cases")
  
    print("VLDT-2-A")
    output("Ianmeister_M", "testest85092")
  
    print("VLDT-2-B")
    output("MenseI", "passPass_4321")
  
    print("VLDT-2-C")
    output("IanMe1", "Mense_is_best1")
  
    # Daniel's Test Cases
    print("Daniel's Cases")
  
    print("VLDT-3-A")
    output("DanTheMan", "manMANMAN")
  
    print("VLDT-3-B")
    output("DanMS", "Cse_453")
  
    print("VLDT-3-C")
    output("Daniel_1", "Byu_CSE453")
  
    # Megan's Test Cases
    print("Megan's Cases")
  
    print("VLDT-4-A")
    output("LadyMegan", "rule_da_world123")
  
    print("VLDT-4-B")
    output("Megmeg1", "BYUI_is_1")
  
    print("VLDT-4-C")
    output("MSchauers1", "CSE_453_student")
  
# Vulnerability tests
def vulnerability_tests():
    print("\n\nUnion Query Attacks")
  
    print("VULT-1-A")
    output("Root", "nothing' UNION SELECT authenticate FROM passwordList")
  
    print("VULT-1-B")
    output("Root", "anything' UNION SELECT * FROM passwordList")

    print("Tautology Attack") 
    
    print("VULT-2-A")
    output("Root", "nothing' OR 'x' = 'x")
  
    print("VULT-2-B")
    output("Root", "anything' OR 'y' = 'y")

    print("Comment Attack")
  
    print("VULT-3-A")
    output("Root'; --", "nothing")
  
    print("VULT-3-B")
    output("Admin'; --", "nothing")

    print("Additional Statement Attack")
    print("VULT-4-A")
    output("Root", "nothing'; INSERT INTO passwordList (name, passwd) VALUES 'Bob', '1234")
  
    print("VULT-4-B")
    output("Admin", "anything'; INSERT INTO passwordList (name, passwd) VALUES 'Alice', '3467")


# Main menu that comes up at the start of the program
def menu():
    while True:
        print("""\nWelcome to the SQL Injection Test

        We will be testing different inputs against a SQL Server.

        Please enter one of the following:
        1. Valid Input Tests
        2. Vulnerability Tests
        3. Manual test
        4. Quit\n""")

        # Requests the user input a number to select one of the menu items
        userinput = input(str("Enter input: "))
        # Valid tests that were created for each of the Group 8 teammates
        if userinput == "1":
            valid_tests()
        # Vulnerability tests for each of the four different types of SQL input attacks
        elif userinput == "2":
            vulnerability_tests()
        # Code that allow a user to test out the code through manual input
        elif userinput =="3":
          #Entering in username
          userN = input("Please enter your username: ")
          #Entering in password
          password = input("Please enter your password: ")
          #passing username and password variables to the output which will run a check on kind of possible           attack maybe occuring
          output(userN,password)
        # Exits program
        elif userinput =="4":
            break
        # Requests valid input
        else:
          print("Please enter a valid number 1-4. Thank you.")

if __name__ == "__main__":
    menu()
