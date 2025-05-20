document.addEventListener("DOMContentLoaded", function () {
    var sidebarToggle = document.getElementById("sidebarToggle");
    var wrapper = document.getElementById("wrapper");

    sidebarToggle.addEventListener("click", function (e) {
        e.preventDefault();
        wrapper.classList.toggle("toggled");
    });
});
