import socket as socket_module
import time
import threading
import re
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import json



script_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(script_dir)


user_login_status = {
    "register": "",
    "login": ""

}


message_for_server = ""
message_for_server_semaphore = threading.Semaphore(1)



#-------------------- client setup--------------------
# This function sets up the client and connects it to the server
def client_setup_and_connect():
    global client_socket
    client_socket = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM)
    server_ip = "10.239.30.82"
    server_port = 12345
    client_socket.connect((server_ip, server_port))
    print("Connected to server")

#-------------------- Code that lets Client send a message--------------------
# This function lets the Client to send a command to the server


def handle_HTTP_requests():
    class Myhandler(BaseHTTPRequestHandler):
        def do_GET(self):
            global count
            global message_for_server
            parsed = urlparse(self.path)
            path = parsed.path

            if path == "/":
                try:
                    with open("index.html", "rb") as f:
                        content_html = f.read()

                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(content_html)
                except Exception as e:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write("index.html not found".encode())
            if path == "/home":
                try:
                    with open("home.html", "rb") as f:
                        content_html = f.read()

                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(content_html)
                except Exception as e:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write("index.html not found".encode())
            file_path = path.lstrip("/")
            if os.path.isfile(file_path):
                # Guess content type
                if file_path.endswith(".css"):
                    content_type = "text/css"
                elif file_path.endswith(".js"):
                    content_type = "application/javascript"
                elif file_path.endswith(".png"):
                    content_type = "image/png"
                elif file_path.endswith(".jpg") or file_path.endswith(".jpeg"):
                    content_type = "image/jpeg"
                elif file_path.endswith(".ico"):
                    content_type = "image/x-icon"
                else:
                    content_type = "application/octet-stream"
                try:
                    with open(file_path, "rb") as f:
                        content = f.read()
                    self.send_response(200)
                    self.send_header("Content-type", content_type)
                    self.end_headers()
                    self.wfile.write(content)
                except Exception as e:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(f"Could not load {file_path}".encode())
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write("Oi! not a valid command".encode())
                


        def do_POST(self):
            global message_for_server
            global client_socket
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)

            post_data_str = post_data.decode("utf-8")

            data = json.loads(post_data_str)

            command = data.get("JSONcommand")

            match command:

                case "register":
                    register_username = data.get("JSONname")
                    register_password = data.get("JSONpassword")
                    with message_for_server_semaphore:
                        message_for_server = f"command = {command};+;username = {register_username};+;password = {register_password}"
                        print("parsed message for server = ", message_for_server)
                    # client_socket.settimeout(1)
                    # try:
                    # client_socket.send(message_for_server.encode("utf-8"))
                    # register_check = client_socket.recv(1024).decode("utf-8")
                    print("on registering, this was received from the server ", user_login_status)
                    register_check = user_login_status["register"]
                    while register_check == "":
                        a = 1
                        register_check = user_login_status["register"]
                    print("got out of while")
                    if register_check == True:
                        response = {
                            "target" : "home",
                            "registration_status" : "successful",
                            "test" : "Test Passed"
                        }
                        response_bytes = json.dumps(response).encode("utf-8")
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(response_bytes)))
                        self.end_headers()
                        self.wfile.write(response_bytes)
                    else:
                        response = {
                            "registration_status" : register_check 
                        }
                        response_bytes = json.dumps(response).encode("utf-8")
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(response_bytes)))
                        self.end_headers()
                        self.wfile.write(response_bytes)
                    # except:
                    #     print("cannot send command")

                case "login":
                    login_username = data.get("JSONname")
                    login_password = data.get("JSONpassword")
                    with message_for_server_semaphore:
                        message_for_server = f"command = {command};+;username = {login_username};+;password = {login_password}"
                    # client_socket.settimeout(1)
                    # try:
                    # client_socket.send(message_for_server.encode("utf-8"))

                    # time.sleep(1)
                    print("on logging in, this was received from the server ", user_login_status)
                    login_check = user_login_status["login"]
                    while login_check == "":
                        a = 1
                        login_check = user_login_status["login"]
                    print("came out of while")
                    if login_check == True:
                        response = {
                            "target" : "home",
                            "login_status" : "successful",
                            "test" : "Test Passed"
                        }
                        response_bytes = json.dumps(response).encode("utf-8")
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(response_bytes)))
                        self.end_headers()
                        self.wfile.write(response_bytes)
                        print("response sent to browser")
                    else:
                        response = {
                            "login_status" : login_check 
                        }
                        response_bytes = json.dumps(response).encode("utf-8")
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(response_bytes)))
                        self.end_headers()
                        self.wfile.write(response_bytes)
                        print("response sent to browser")

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
    
    server_address = ("", 8000)

    httpd = HTTPServer(server_address, Myhandler)
    print("Server started at http://localhost:8000")
    httpd.serve_forever()


def send_formatted_string_to_server():
    global message_for_server
    while True:
        # print("message to be sent to the server = ", message_for_server)
        if len(message_for_server) > 0:
            client_socket.send(message_for_server.encode("utf-8"))
            print("message sent to server = ", message_for_server)
            with message_for_server_semaphore:
                message_for_server = ""





def receive_from_server():
    global client_socket
    global user_login_status
    command_pattern = r"command = (.*?);\+\;"
    username_pattern = r"username = (.*?);\+\;"
    message_pattern = r"message = (.*)"
    operation_status_pattern = r"operation_status = (.*)"
    log = []
    while True:
        # client_socket.settimeout(1)# YE GALAT HAI! AGAR TIMER LAGA DIYA TO POORA SAMAY VO 1 SEC WAIT KAREGA AUR KOI MESSAGE NAHI AAYA TO POORA TIME PRINT KARTA RAHEGA KI MEESSAGE NOT RECEIVED
        # try:
        message_from_server = client_socket.recv(1024).decode("utf-8")
        print("received = ", message_from_server)
        command = re.search(command_pattern, message_from_server).group(1)
        print("found command = ", command)
        operation_status = re.search(operation_status_pattern, message_from_server).group(1)
        print("found operation status = ", operation_status)

        if command == "register" and operation_status == "True":
            user_login_status["register"] = True
            user_login_status["login"] = True
        if command == "login" and operation_status == "True":
            user_login_status["register"] = True
            user_login_status["login"] = True
        if command == "login" and operation_status == "False":
            user_login_status["register"] = False
            user_login_status["login"] = False
        if command == "register" and operation_status == "False":
            user_login_status["register"] = False
            user_login_status["login"] = False
        print("user_login_status = ", user_login_status)
        

        # if  message_from_server == "you have logged in" or message_from_server == "user already exists":
        #     print(message_from_server)
        

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
        if command == "chat":
            message = re.search(message_pattern, message_from_server).group(1)
            # if match_command == "register" or match_command == "login":
            #     if match_status == "unsuccessful":
            #         print(f"{match_command} unsuccessful")
            #     if match_status == "successful":
            #         print(f"{match_command} successful")
            # if match_command == "chat":
                # if match_status == "successful":
            # print(match_message)
                # else:
                #     print("could not send your message")
                


def main():
    client_setup_and_connect()
    handle_HTTP_requests_thread = threading.Thread(target = handle_HTTP_requests)
    receive_from_server_thread = threading.Thread(target = receive_from_server)
    send_formatted_string_to_server_thread = threading.Thread(target = send_formatted_string_to_server)
    handle_HTTP_requests_thread.start()
    send_formatted_string_to_server_thread.start()
    receive_from_server_thread.start()
    # take_command.start()
    # receive_from_server.start()


if __name__ == "__main__":
    main()


