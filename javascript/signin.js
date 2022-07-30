let ftcNumber;
let name;
let password;
let email;
let storedName;
function signIn() {
    ftcNumber = document.getElementById("ftcNumber")
    name = document.getElementById("name");
    storedName = localStorage.setItem('name', name);
    password = document.getElementById("discordID");
    email = document.getElementById("email");
    console.log("");
    //fetch()
}