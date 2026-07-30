// ==============================
// DeepSpace CyberShield AI
// intro.js
// ==============================

// Wait until page loads
window.addEventListener("load", () => {

    const loader = document.getElementById("loader");

    // Hide loading screen after 3 seconds
    setTimeout(() => {

        if (loader) {

            loader.style.opacity = "0";

            loader.style.visibility = "hidden";

        }

    }, 3000);

});

// ==============================
// Loading Messages
// ==============================

const loadingMessages = [

    "Initializing AI Engine...",
    "Loading Isolation Forest...",
    "Loading TTL Evidence...",
    "Loading Dynamic Trust...",
    "Loading DSSLV...",
    "Launching Mission Control..."

];

let messageIndex = 0;

const loadingText = document.getElementById("loading-text");

if (loadingText) {

    setInterval(() => {

        messageIndex++;

        if (messageIndex >= loadingMessages.length) {

            messageIndex = 0;

        }

        loadingText.innerHTML = loadingMessages[messageIndex];

    }, 500);

}

// ==============================
// Smooth Scroll
// ==============================

document.querySelectorAll('a[href^="#"]').forEach(anchor => {

    anchor.addEventListener("click", function (e) {

        e.preventDefault();

        const target = document.querySelector(this.getAttribute("href"));

        if (target) {

            target.scrollIntoView({

                behavior: "smooth"

            });

        }

    });

});

// ==============================
// Navbar Background on Scroll
// ==============================

window.addEventListener("scroll", () => {

    const nav = document.querySelector("nav");

    if (!nav) return;

    if (window.scrollY > 60) {

        nav.classList.add("nav-scroll");

    }

    else {

        nav.classList.remove("nav-scroll");

    }

});

// ==============================
// Scroll Reveal Animation
// ==============================

const observer = new IntersectionObserver(entries => {

    entries.forEach(entry => {

        if (entry.isIntersecting) {

            entry.target.classList.add("show");

        }

    });

}, {

    threshold: 0.2

});

document.querySelectorAll("section").forEach(section => {

    section.classList.add("hidden");

    observer.observe(section);

});

// ==============================
// Hero Button Animation
// ==============================

const heroButton = document.querySelector(".primary-btn");

if (heroButton) {

    heroButton.addEventListener("mouseenter", () => {

        heroButton.style.transform = "scale(1.05)";

    });

    heroButton.addEventListener("mouseleave", () => {

        heroButton.style.transform = "scale(1)";

    });

}

// ==============================
// Typing Effect
// ==============================

const heroTitle = document.querySelector(".hero-left h1");

if (heroTitle) {

    const text = heroTitle.textContent;

    heroTitle.textContent = "";

    let i = 0;

    function typeWriter() {

        if (i < text.length) {

            heroTitle.textContent += text.charAt(i);

            i++;

            setTimeout(typeWriter, 40);

        }

    }

    typeWriter();

}

console.log("🚀 DeepSpace CyberShield AI Loaded Successfully");