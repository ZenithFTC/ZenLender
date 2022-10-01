let storedName, shoppingList, shoppingBag, dynamicHTML, answer, cartList;
function getUsername() {
    storedName = localStorage.getItem('name');
    if(storedName!=null) {
        document.getElementById('title').innerHTML = 'Hi, ' + storedName;
    }
    document.getElementById('shoppingCart').hidden= true
    console.log('Inside Onload');
}
async function checkout(event) {
    //dynamicHTML = ''
    event.preventDefault()
    shoppingBag = localStorage.getItem('bag')
    console.log(shoppingBag)
    dynamicHTML= "";
    axios.get('https://fetchFTC.py201678.repl.co/generatehtml/' + shoppingBag)
        .then(function (response) {
            console.log(response.data)
            document.getElementById('shoppingCartList').innerHTML = response.data
        })
        .catch(function (error) {
            console.log(error);
        })
        .then(function () {

            console.log(dynamicHTML)
            console.log("done");
        });
    axios.get('https://fetchFTC.py201678.repl.co/generateprice/' + shoppingBag)
        .then(function (response) {
            console.log(response.data)
            document.getElementById('totalPrice').innerHTML = response.data
        })
        .catch(function (error) {
            console.log(error);
        })
        .then(function () {

            console.log(dynamicHTML)
            console.log("done");
        });

    document.getElementById('shoppingCart').hidden = false;
}
function closeCheckout(event) {
    document.getElementById('shoppingCart').hidden=true;
    event.preventDefault();
}
function goToSignUp() {
    window.location.href = "../signup.html"
}
function generateHTML(res) {
    dynamicHTML = dynamicHTML + `
<li class="flex py-6">
                                                <div class="h-24 w-24 flex-shrink-0 overflow-hidden rounded-md border border-gray-200">
                                                    <img src="https://tailwindui.com/img/ecommerce-images/shopping-cart-page-04-product-01.jpg" alt="Salmon orange fabric pouch with match zipper, gray zipper pull, and adjustable hip belt." class="h-full w-full object-cover object-center">
                                                </div>

                                                <div class="ml-4 flex flex-1 flex-col">
                                                    <div>
                                                        <div class="flex justify-between text-base font-medium text-gray-900">
                                                            <h3>
                                                                <a href="#">${res.partName}</a>
                                                            </h3>
                                                            <p class="ml-4">$${res.price}</p>
                                                        </div>
                                                        <p class="mt-1 text-sm text-gray-500">${res.partInitials}</p>
                                                    </div>
                                                    <div class="flex flex-1 items-end justify-between text-sm">
                                                        <p class="text-gray-500">Qty 1</p>

                                                        <div class="flex">
                                                            <button type="button" class="font-medium text-indigo-600 hover:text-indigo-500">Remove</button>
                                                        </div>
                                                    </div>
                                                </div>
                                            </li>`
}