import socket as socket_module
import threading
import re
import time
import bcrypt
from password_strength import PasswordPolicy
from pymongo import MongoClient



registered_users = {}
thread_list = []




def connect_to_db():
    db_connection_to_server = MongoClient("mongodb://localhost:27017/")
    db = db_connection_to_server["server"]
    collection = db["registered_users"]
    return collection

def generate_username_list(collection):
    #print("type of collection object is -------->",type(collection))
    username_list = []
    results = collection.find()
    for doc in results:
        username_list.append(doc["username"])
    return username_list

def make_thread_for_new_client(client_socket, registered_users_update_semaphore, collection):
    thread_object = threading.Thread(target = handle_client_messages, args = (client_socket, registered_users_update_semaphore, collection))
    thread_object.start()
    thread_list.append(thread_object)


#-------------------- Server Setup --------------------
# This part of code starts the server
def start_server():
    server_socket = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM)
    host = "192.168.1.3"
    port = 12345
    server_socket.bind((host, port))
    server_socket.listen(5)
    registered_users_update_semaphore = threading.Semaphore(1)
    print("Server switched on")
    collection = connect_to_db()
    while True:
        client_socket,client_ip_and_port = server_socket.accept()
        make_thread_for_new_client(client_socket, registered_users_update_semaphore, collection)

        
#-------------------- receive formatted string --------------------
#this function receives the formatted string from the client 
def receive_formatted_string(client_socket):
    formatted_string = client_socket.recv(1024).decode("utf-8")
    return formatted_string
    
#-------------------- parse formatted string --------------------
#this function separates and stores command, username, password/message from the received formatted string into a dictionary
def parse_formatted_string(arg_formatted_string):
    separated_fields_dict = {}
    command_pattern = r"command = (.*?);\+\;"
    username_pattern = r"username = (.*?);\+\;"
    message_pattern = r"message = (.*)"
    password_pattern = r"password = (.*)"
    match_command = re.search(command_pattern, arg_formatted_string).group(1)
    match_username = re.search(username_pattern, arg_formatted_string).group(1)
    if match_command == "chat":
        match_message = re.search(message_pattern, arg_formatted_string).group(1)
        separated_fields_dict["message"] = match_message
    else:
        match_password = re.search(password_pattern, arg_formatted_string).group(1)
        separated_fields_dict["password"] = match_password
    separated_fields_dict["command"] = match_command
    separated_fields_dict["username"] = match_username
    print(separated_fields_dict)
    return separated_fields_dict

def password_policy_check(arg_separated_fields_dict):
    policy = PasswordPolicy.from_names(
    length=6,           # min length: 8
    uppercase=1,        # need min. 1 uppercase letter
    numbers=1,          # need min. 1 digit
    special=1,          # need min. 1 special character
    )
    password = arg_separated_fields_dict["password"]
    violations = policy.test(password)
    if not violations:
        return True
    else:
        return False
#-------------------- register/add new user --------------------
#this function will handle register command given to the server as it adds a new user to registered_users
def add_new_user(arg_separated_fields_dict, client_socket, registered_users_update_semaphore, collection):#separated fields dict will be passed as an argument here and in all the following functions
    global registered_users
    username_list = generate_username_list(collection)
    username = arg_separated_fields_dict["username"]
    # password = arg_separated_fields_dict["password"]
    with registered_users_update_semaphore:
        if username not in username_list:
            
            # time.sleep(3)
            insert_data = {"username": username}
            collection.insert_one(insert_data)
            registered_users[username] = {"login_flag": False, "client_socket": client_socket}
            client_socket.send("you have registered".encode("utf-8"))
            user_already_exists = False
        else:
            client_socket.send("user already exists".encode("utf-8"))
            user_already_exists = True
    # print("registered users: ", registered_users)
    return user_already_exists
    
    
#-------------------- assign salt --------------------
#this function assigns a random sort to a new user so that they could use it again during login process
def assign_salt_to_new_user(arg_separated_fields_dict, collection):
    # print("assign salt to new user")
    salt_for_new_user = bcrypt.gensalt()
    username = arg_separated_fields_dict["username"]
    # registered_users[username]["salt"] = salt_for_new_user
    condition = {"username": username}
    update_field = {"$set": {"salt": salt_for_new_user}}
    collection.update_one(condition, update_field)


#-------------------- hash password --------------------
#this function hashes the plain password and stores it in the registered_users dict
def hash_and_store_password(arg_separated_fields_dict, collection):
    # print("entered hash and store password")
    username = arg_separated_fields_dict["username"]
    # salt = registered_users[username]["salt"]
    salt = collection.find_one({"username": username})
    salt = salt["salt"]
    password = arg_separated_fields_dict["password"]
    password = password.encode("utf-8")
    hashed_password = bcrypt.hashpw(password, salt)
    # registered_users[username]["password"] = hashed_password
    condition = {"username": username}
    update_field = {"$set": {"password": hashed_password}}
    collection.update_one(condition, update_field)
    print("registered users = ", registered_users)

def login_password_to_hashvalue(arg_separated_fields_dict, collection):
    password = arg_separated_fields_dict["password"]
    password = password.encode("utf-8")
    username = arg_separated_fields_dict["username"]
    salt = collection.find_one({"username": username})
    salt = salt["salt"]
    hashed_password = bcrypt.hashpw(password, salt)
    print("hashed password = ", hashed_password)
    return hashed_password



#-------------------- validity check of fields-------------------- 
#this function checks if the supplied information is correct or not 
def validity_check(arg_separated_fields_dict, hashed_password, collection):
    username_valid = False
    password_valid = False
    this_username = arg_separated_fields_dict["username"]
    # this_user_password = arg_separated_fields_dict["password"]
    username_list = generate_username_list(collection)
    if this_username in username_list:
        username_valid = True
        saved_password = collection.find_one({"username": this_username})
        saved_password = saved_password["password"]
        if saved_password == hashed_password:
            password_valid = True
        else:
            print("wrong password")
    else:
        print("invalid username")
    return username_valid, password_valid, this_username

#-------------------- update login_flag--------------------
#this function updates the login_flag in the registered users if username and password are valid
def update_registered_users(argtuple, arg_separated_fields_dict, client_socket):
    this_username = argtuple[2]
    if (argtuple[0],argtuple[1]) == (True, True) and this_username in registered_users.keys():
        registered_users[this_username] = {"login_flag": True, "client_socket": client_socket}
        print(f"{arg_separated_fields_dict["username"]} logged in")
    else:
        print(f"{arg_separated_fields_dict["username"]}'s login request failed")
    

#-------------------- modify message--------------------
#this function merges name of sender with the message

def merge_name(arg_sendername, arg_message):
    modified_message = arg_sendername + ":" + arg_message
    return modified_message

#-------------------- send message to receiver--------------------
#this message sends the message to the intended user

def send_message(arg_receiver_name, arg_message):
    final_message = f"command = chat;+;username = {arg_receiver_name};+;message = {arg_message}"
    receiver_socket = registered_users[arg_receiver_name]["client_socket"]
    receiver_socket.send(final_message.encode("utf-8"))


#-------------------- target function--------------------
#this function is the primary function that the thread will call
def handle_client_messages(client_socket, registered_users_update_semaphore, collection):
    while True:
        formatted_string = receive_formatted_string(client_socket)
        separated_fields_dict = parse_formatted_string(formatted_string)
        match separated_fields_dict["command"]:
            case "register":
                # policy_check = password_policy_check(separated_fields_dict)
                # if policy_check == True:
                user_already_exists = add_new_user(separated_fields_dict, client_socket, registered_users_update_semaphore, collection)
                if user_already_exists == True:
                    continue
                assign_salt_to_new_user(separated_fields_dict, collection)
                hash_and_store_password(separated_fields_dict, collection)
                # else:
                    # print(f"cannot register {separated_fields_dict["username"]} as password did not follow rules")
            case "login":
                hashed_password = login_password_to_hashvalue(separated_fields_dict, collection)
                validity_and_username = validity_check(separated_fields_dict, hashed_password, collection)
                with registered_users_update_semaphore:
                    update_registered_users(validity_and_username, separated_fields_dict, client_socket)
            case "chat":
                modified_message = merge_name(validity_and_username[2], separated_fields_dict["message"])
                send_message(separated_fields_dict["username"], modified_message)

    
        


#-------------------- making threads --------------------
#this part makes new threads for each connection





def main():
    start_server()


collection = connect_to_db()
all_users = generate_username_list(collection)
for i in all_users:
    registered_users[i] = None
main()

