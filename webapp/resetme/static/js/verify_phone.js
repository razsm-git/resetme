let enableTime = new Date().getTime() + 120000;
check = function toggleButton() {
            var retry_code_btn = document.getElementById('retry_code')
            let currentDate = new Date();
            if (currentDate.getTime() > enableTime) {
                retry_code_btn.disabled = false;
                retry_code_btn.classList.remove("btn-disabled");
                retry_code_btn.classList.add("btn-next");
                retry_code_btn.removeAttribute("title");
                clearInterval(interval);
            }
        }
check.call();
interval = setInterval(check, 5000);
