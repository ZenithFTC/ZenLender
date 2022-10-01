let ftcNumber;
let name;
let discordID;
let email;

function signup() {
    ftcNumber = document.getElementById("ftcNumber")
    localStorage.setItem('ftcNumber', ftcNumber);
    name = document.getElementById("name");
    localStorage.setItem('name', name);
    discordID = document.getElementById("discordID");
    localStorage.setItem('discordID', discordID);
    email = document.getElementById("email");
    localStorage.setItem('email', email)
    console.log("");
    //fetch()
}