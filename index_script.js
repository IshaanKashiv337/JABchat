x = 10
console.log(x)
const toggle_login = document.getElementById("toggle_login")
const toggle_register = document.getElementById("toggle_register")
const username = document.getElementById("username_input")
const password = document.getElementById("password_input")
const login_button = document.getElementById("login_button")

command = ""
username_value = ""
password_value = ""

function change_bg_and_text_color(element) {
    element.style.backgroundColor = "black"
    element.style.color = "#ffc42c"
}

function reverse_changes(element) {
    element.style.backgroundColor = "#ffc42c"
    element.style.color = "black"
}

function click_on_input(event, element, id) {
    event.stopPropagation()
    document.getElementById(id).value = ""
    element.style.backgroundColor = "black"
    element.style.color = "#ffc42c"
}

function handle_click_on_input(element, id) {
    return function (event) {
        click_on_input(event, element, id)
    }
}

function if_clicked_outside() {
    reverse_changes(toggle_login)
    reverse_changes(toggle_register)
    reverse_changes(username)
    reverse_changes(password)
}

toggle_login.addEventListener("mouseover", () => change_bg_and_text_color(toggle_login))
toggle_login.addEventListener("mouseout", () => reverse_changes(toggle_login))
toggle_login.addEventListener("click", () => {
    command = "login"
    document.getElementById("login_button").textContent = "Login"
    change_bg_and_text_color(toggle_login)
})


toggle_register.addEventListener("mouseover", () => change_bg_and_text_color(toggle_register))
toggle_register.addEventListener("mouseout", () => reverse_changes(toggle_register))
toggle_register.addEventListener("click", () => {
    command = "register"
    document.getElementById("login_button").textContent = "Register"
})


username.addEventListener("mouseover", () => change_bg_and_text_color(username))
username.addEventListener("click", handle_click_on_input(username, "username_input"))
username.addEventListener("mouseout", () => reverse_changes(username))

password.addEventListener("mouseover", () => change_bg_and_text_color(password))
password.addEventListener("click", handle_click_on_input(password, "password_input"))
password.addEventListener("mouseout", () => reverse_changes(password))

login_button.addEventListener("mouseover", () => reverse_changes(login_button))
login_button.addEventListener("mouseout", () => change_bg_and_text_color(login_button))
login_button.addEventListener("click", () => {
    username_value = document.getElementById("username_input").value
    password_value = document.getElementById("password_input").value
    const request = new XMLHttpRequest
    request.open("POST", "http://localhost:8000/", true)
    request.onload = function () {
        if (request.status === 200) {
            // console.log(responseText)
            server_response = JSON.parse(request.responseText)
            console.log(server_response)
            if (Object.keys(server_response).includes("registration_status")) {
                console.log(server_response.registration_status)
                if (server_response.registration_status === "successful") {
                    window.location.href = server_response.target;
                }
                else {
                    console.log("executed else block")
                    alert("Username taken, try a different one")
                }
            }
            else if (Object.keys(server_response).includes("login_status")) {
                console.log(server_response.login_status)
                if (server_response.login_status === "successful") {
                    window.location.href = server_response.target;
                }
                else {
                    console.log("executed else block")
                    alert("Wrong Username or Password")
                }
            }
        }
    }
    data = JSON.stringify({
        JSONcommand: command,
        JSONname: username_value,
        JSONpassword: password_value

    })
    request.send(data)
})

document.addEventListener("click", if_clicked_outside)















