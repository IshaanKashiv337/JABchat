const message_bar = document.getElementById("message_bar")
const username = document.getElementById("username") 
const feedback = document.getElementById("feedback") 
const client2 = document.getElementById("client2")

message_flag = 0


function change_bg_and_text_color(element){
    element.style.backgroundColor = "black"
    element.style.color = "#ffc42c"
}

function reverse_changes(element){
    element.style.backgroundColor = "#ffc42c"
    element.style.color = "black"
}

message_bar.addEventListener("click", ()=> {
    val = document.getElementById("message_bar").value
    if (val == "message" && message_flag == 0){
        document.getElementById("message_bar").value = ""
        message_flag = 1
    }
})
document.addEventListener("click", ()=> reverse_changes(message_bar))

username.addEventListener("mouseover", ()=>{
    username.style.color = "black"
} )
username.addEventListener("mouseout", ()=>{
    username.style.color = "#ffc42c"
})

feedback.addEventListener("mouseover", ()=> {
    feedback.style.color = "black"
})

feedback.addEventListener("mouseout", ()=> {
    feedback.style.color = "#ffc42c"
})
client2.addEventListener("mouseover", ()=> {
    client2.style.color = "black"
})

client2.addEventListener("mouseout", ()=> {
    client2.style.color = "#ffc42c"
})



