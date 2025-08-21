import socket as socket_module
import time
import threading
import re

#-------------------- client setup--------------------
# This function sets up the client and connects it to the server
def client_setup_and_connect():
    global client_socket
    client_socket = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM)
    server_ip = "192.168.1.3"
    server_port = 12345
    client_socket.connect((server_ip, server_port))
    print("Connected to server")

#-------------------- Code that lets Client send a message--------------------
# This function lets the Client to send a command to the server


def show_options_and_send_command_to_server():
    while True:
        print()
        print("register")
        print("login")
        print("chat")
        print()
        command = input("Please enter one of the above options:")

        match command:

            case "register":
                register_username = input("enter username:")
                register_password = input("enter password:")
                message_for_server = f"command = {command};+;username = {register_username};+;password = {register_password}"
                # client_socket.settimeout(1)
                # try:
                client_socket.send(message_for_server.encode("utf-8"))
                # except:
                #     print("cannot send command")

            case "login":
                login_username = input("enter username:")
                login_password = input("enter password:")
                message_for_server = f"command = {command};+;username = {login_username};+;password = {login_password}"
                # client_socket.settimeout(1)
                # try:
                client_socket.send(message_for_server.encode("utf-8"))
                # except:
                #     print("cannot send command")
            case "chat":
                # global destination_user_online
                chat_username = input("enter username you want to chat with")
                time.sleep(2)
                # if it is possible, set a flag(destination_user_online) as true and that flag lets the chat to continue
                # if destination_user_online == True:
                while True:
                    message = input(f"message for {chat_username}:")
                    if message == "terminate chat":
                        print(f"ending chat with {chat_username}")
                        break
                    message_for_server = f"command = {command};+;username = {chat_username};+;message = {message}"
                    # client_socket.settimeout(1)
                    # try: 
                    if len(message) > 0:
                        client_socket.send(message_for_server.encode("utf-8"))
                    # except:
                    #     print("cannot send message")
                # else:
                #     print("mentioned user is offline")

def receive_messages_and_acknowledgement_from_server():
    command_pattern = r"command = (.*?);\+\;"
    username_pattern = r"username = (.*?);\+\;"
    message_pattern = r"message = (.*)"
    status_pattern = r"status = (.*?);\+\;"
    log = []
    while True:
        # client_socket.settimeout(1)# YE GALAT HAI! AGAR TIMER LAGA DIYA TO POORA SAMAY VO 1 SEC WAIT KAREGA AUR KOI MESSAGE NAHI AAYA TO POORA TIME PRINT KARTA RAHEGA KI MEESSAGE NOT RECEIVED
        # try:
        message_from_server = client_socket.recv(1024).decode("utf-8")
        if message_from_server == "user already exists" or message_from_server == "you have logged in":
            print(message_from_server)
        else:

            # except:
            #     print("cannot receive acknowledgement/message")
            # if message_from_server == "receiver ready":
            #     destination_user_online = True
            #     continue
            # elif message_from_server == "receiver not ready":
            #     print("destination user not online")
            #     continue
            # match_command = re.search(command_pattern, message_from_server)
            # match_username = re.search(username_pattern, message_from_server)
            # match_status = re.search(status_pattern, message_from_server)
            match_message = re.search(message_pattern, message_from_server).group(1)
            # if match_command == "register" or match_command == "login":
            #     if match_status == "unsuccessful":
            #         print(f"{match_command} unsuccessful")
            #     if match_status == "successful":
            #         print(f"{match_command} successful")
            # if match_command == "chat":
                # if match_status == "successful":
            print(match_message)
                # else:
                #     print("could not send your message")
                


def main():
    client_setup_and_connect()
    take_command = threading.Thread(target = show_options_and_send_command_to_server)
    receive_from_server = threading.Thread(target = receive_messages_and_acknowledgement_from_server)
    take_command.start()
    receive_from_server.start()


main()



