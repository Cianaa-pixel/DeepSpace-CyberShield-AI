/* ==========================================================
   DeepSpace CyberShield AI
   intro.js
   Premium Intro + Scroll Animations + UI Effects
========================================================== */

document.addEventListener("DOMContentLoaded", () => {

    /* ======================================================
       ELEMENTS
    ====================================================== */

    const loader = document.getElementById("loader");
    const loaderBox = document.querySelector(".loader-box");
    const loaderTitle = document.querySelector(".loader-box h1");
    const navbar = document.querySelector("nav");

    const hero = document.querySelector("#hero");
    const heroLeft = document.querySelector(".hero-left");
    const heroRight = document.querySelector(".hero-right");


    /* ======================================================
       PREVENT FLASH
    ====================================================== */

    if (navbar) {
        navbar.style.opacity = "0";
        navbar.style.transform = "translateX(-50%) translateY(-30px)";
    }

    if (heroLeft) {
        heroLeft.style.opacity = "0";
        heroLeft.style.transform = "translateY(40px)";
    }

    if (heroRight) {
        heroRight.style.opacity = "0";
        heroRight.style.transform = "translateY(40px)";
    }


    /* ======================================================
       REMOVE OLD LOADING BAR
    ====================================================== */

    const progress = document.querySelector(".progress");

    if (progress) {
        progress.style.display = "none";
    }

    const loadingText = document.querySelector("#loading-text");

    if (loadingText) {
        loadingText.style.display = "none";
    }


    /* ======================================================
       INTRO TITLE
    ====================================================== */

    if (loaderTitle) {

        const originalText =
            "DeepSpace CyberShield AI";

        loaderTitle.textContent = "";

        loaderTitle.style.opacity = "1";

        loaderTitle.style.transform = "scale(1)";

        loaderTitle.style.transition =
            "opacity 1s ease, transform 1s ease";

        let index = 0;


        /* -----------------------------------------------
           TYPE LETTER BY LETTER
        ----------------------------------------------- */

        function typeTitle() {

            if (index < originalText.length) {

                loaderTitle.textContent +=
                    originalText[index];

                index++;

                setTimeout(typeTitle, 75);

            } else {

                /* After typing finishes */

                setTimeout(() => {

                    fadeIntro();

                }, 1000);

            }

        }


        /* =================================================
           FADE INTRO
        ================================================= */

        function fadeIntro() {

            loaderTitle.style.opacity = "0";

            loaderTitle.style.transform =
                "scale(1.15)";

            if (loaderBox) {

                loaderBox.style.transition =
                    "opacity 1s ease, transform 1s ease";

                loaderBox.style.opacity = "0";

                loaderBox.style.transform =
                    "scale(1.08)";

            }


            setTimeout(() => {

                if (loader) {

                    loader.style.opacity = "0";

                    loader.style.pointerEvents =
                        "none";

                    loader.style.transition =
                        "opacity 1s ease";

                }


                /* -----------------------------------------
                   SHOW WEBSITE
                ----------------------------------------- */

                setTimeout(() => {

                    if (loader) {
                        loader.style.display = "none";
                    }

                    showWebsite();

                }, 700);

            }, 700);

        }


        /* =================================================
           START INTRO
        ================================================= */

        setTimeout(() => {

            typeTitle();

        }, 400);

    } else {

        showWebsite();

    }


    /* ======================================================
       SHOW MAIN WEBSITE
    ====================================================== */

    function showWebsite() {

        /* -----------------------------------------------
           NAVBAR POP
        ----------------------------------------------- */

        if (navbar) {

            navbar.style.transition =
                "opacity .8s ease, transform .8s cubic-bezier(.17,.67,.3,1.3)";

            navbar.style.opacity = "1";

            navbar.style.transform =
                "translateX(-50%) translateY(0)";

        }


        /* -----------------------------------------------
           HERO LEFT
        ----------------------------------------------- */

        setTimeout(() => {

            if (heroLeft) {

                heroLeft.style.transition =
                    "opacity 1s ease, transform 1s ease";

                heroLeft.style.opacity = "1";

                heroLeft.style.transform =
                    "translateY(0)";

            }

        }, 250);


        /* -----------------------------------------------
           HERO RIGHT
        ----------------------------------------------- */

        setTimeout(() => {

            if (heroRight) {

                heroRight.style.transition =
                    "opacity 1.2s ease, transform 1.2s ease";

                heroRight.style.opacity = "1";

                heroRight.style.transform =
                    "translateY(0)";

            }

        }, 500);


        /* -----------------------------------------------
           INITIAL SECTION ANIMATION
        ----------------------------------------------- */

        initializeScrollAnimations();

    }


    /* ======================================================
       NAVBAR SCROLL EFFECT
    ====================================================== */

    window.addEventListener("scroll", () => {

        if (!navbar) return;

        if (window.scrollY > 50) {

            navbar.classList.add("nav-scroll");

        } else {

            navbar.classList.remove("nav-scroll");

        }

    });


    /* ======================================================
       SCROLL REVEAL
    ====================================================== */

    function initializeScrollAnimations() {

        const animatedElements =
            document.querySelectorAll(
                "section, .card, .timeline div, .stat-card, .dashboard-card"
            );


        animatedElements.forEach(element => {

            element.classList.add("hidden");

        });


        const observer =
            new IntersectionObserver(

                entries => {

                    entries.forEach(entry => {

                        if (entry.isIntersecting) {

                            entry.target.classList.add("show");

                            observer.unobserve(
                                entry.target
                            );

                        }

                    });

                },

                {
                    threshold: 0.15
                }

            );


        animatedElements.forEach(element => {

            observer.observe(element);

        });

    }


    /* ======================================================
       BUTTON RIPPLE EFFECT
    ====================================================== */

    const buttons =
        document.querySelectorAll(
            ".primary-btn, .secondary-btn"
        );


    buttons.forEach(button => {

        button.addEventListener(
            "click",
            function(event) {

                const ripple =
                    document.createElement("span");

                ripple.classList.add(
                    "button-ripple"
                );

                const rect =
                    this.getBoundingClientRect();

                const size =
                    Math.max(
                        rect.width,
                        rect.height
                    );

                ripple.style.width =
                    size + "px";

                ripple.style.height =
                    size + "px";

                ripple.style.left =
                    (event.clientX - rect.left - size / 2)
                    + "px";

                ripple.style.top =
                    (event.clientY - rect.top - size / 2)
                    + "px";

                this.appendChild(ripple);


                setTimeout(() => {

                    ripple.remove();

                }, 600);

            }

        );

    });


    /* ======================================================
       CARD MOUSE GLOW
    ====================================================== */

    const cards =
        document.querySelectorAll(
            ".card, .dashboard-card, .stat-card"
        );


    cards.forEach(card => {

        card.addEventListener(
            "mousemove",
            event => {

                const rect =
                    card.getBoundingClientRect();

                const x =
                    event.clientX - rect.left;

                const y =
                    event.clientY - rect.top;


                card.style.setProperty(
                    "--mouse-x",
                    `${x}px`
                );

                card.style.setProperty(
                    "--mouse-y",
                    `${y}px`
                );

            }
        );


        card.addEventListener(
            "mouseleave",
            () => {

                card.style.removeProperty(
                    "--mouse-x"
                );

                card.style.removeProperty(
                    "--mouse-y"
                );

            }
        );

    });


    /* ======================================================
       SMOOTH NAVIGATION
    ====================================================== */

    document.querySelectorAll(
        'nav a[href^="#"]'
    ).forEach(link => {

        link.addEventListener(
            "click",
            event => {

                const targetId =
                    link.getAttribute("href");

                const target =
                    document.querySelector(targetId);

                if (!target) return;

                event.preventDefault();


                target.scrollIntoView({
                    behavior: "smooth",
                    block: "start"
                });

            }
        );

    });


    /* ======================================================
       PARALLAX HERO
    ====================================================== */

    window.addEventListener(
        "mousemove",
        event => {

            if (!heroRight) return;

            const x =
                (event.clientX / window.innerWidth - 0.5);

            const y =
                (event.clientY / window.innerHeight - 0.5);


            heroRight.style.setProperty(
                "--mouse-x",
                `${x * 15}px`
            );

            heroRight.style.setProperty(
                "--mouse-y",
                `${y * 15}px`
            );

        }
    );


    /* ======================================================
       CONSOLE MESSAGE
    ====================================================== */

    console.log(
        "%c🚀 DeepSpace CyberShield AI",
        "color:#00d9ff;font-size:20px;font-weight:bold;"
    );

    console.log(
        "%cAI Defense System Online",
        "color:#00ffb3;font-size:14px;"
    );

});