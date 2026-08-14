document.addEventListener("DOMContentLoaded", function () {

    const search = document.getElementById("emailSearch");

    const emails = document.querySelectorAll(".email-search-item");

    if (!search) return;

    search.addEventListener("keyup", function () {

        const value = this.value.toLowerCase();

        emails.forEach(email => {

            if (email.innerText.toLowerCase().includes(value)) {
                email.style.display = "";
            } else {
                email.style.display = "none";
            }

        });

    });

});