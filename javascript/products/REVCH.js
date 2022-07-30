let bag;
function addToCart(event) {
    bag = localStorage.getItem('bag');
    if(localStorage.getItem('loggedIn')==null){
        window.location.href="../signup.html"
    }
    if(localStorage.getItem('loggedIn') === "true") {
        if(bag==null){
            localStorage.setItem('bag',"RCH;")
        } else {
            localStorage.setItem('bag',bag+"RCH;")
        }
        console.log('added to cart');
    }
    event.preventDefault()
}

