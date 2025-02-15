let form=document.querySelector(".form-login-inner");
let email = document.querySelector("#email-login");
let password = document.querySelector("#password");
let emailicon = document.querySelector(".emailicon");
let passicon = document.querySelector(".passicon");
let errormsg = document.querySelector("#errormsg");
let submitbtn=document.querySelector(".login-button");
let checkemail = () => {
  let pattern = /^[^ ]+@[^ ]+\.[a-z]{2,3}$/;
  if (email.value == "" || !email.value.match(pattern)) {
    emailicon.classList.add("fa-shake");
    emailicon.style.color = "#ec0909";
    return false;
  } else {
    emailicon.classList.replace("fa-envelope", "fa-circle-check");
    emailicon.classList.remove("fa-shake");
    emailicon.style.color = "#00c300";
    return true;
  }
};

let checkpassword = () => {
  let pattern = /^[A-Za-z]\w{7,14}$/;
  if (password.value == "" || !password.value.match(pattern)) {
    passicon.classList.add("fa-shake");
    passicon.style.color = "#ec0909";
    errormsg.style.display = "inline";
    return false;
  } else {
    passicon.style.color = "#00c300";
    errormsg.style.display = "none";
    passicon.classList.remove("fa-shake");
    return true;
  }
};

email.onkeyup=checkemail;
password.onkeyup=checkpassword

passicon.onclick = () => {
  if (password.type == "password") {
    password.setAttribute("type", "text");
    passicon.classList.replace("fa-eye-slash", "fa-eye");
  } else {
    password.setAttribute("type", "password");
    passicon.classList.replace("fa-eye", "fa-eye-slash");
  }
};

// form.addEventListener("submit", (e) => {
//     e.preventDefault();
//     if(emailicon.classList.contains("fa-circle-check") && passicon.style.color=="rgb(0, 195, 0)"){
//         Swal.fire(
//             'Login succesfully ',
//             'Go to your profile page',
//             'success'
//           )
//     }
//     else{
//         Swal.fire(
//             'Enter Valid Input',
//             'login error',
//             'error'
//           )
       
//     }
    
// })



