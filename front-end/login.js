// URL da sua API
const urldaapi = "http://localhost:3000"; // ajuste conforme necessário

// Função de Registro de Usuário
async function register() {
    const username = document.getElementById("register-username").value;
    const password = document.getElementById("register-password").value;

    const response = await fetch(`${urldaapi}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
    });

    if (response.ok) {
        alert("Usuário registrado com sucesso!");
    } else {
        const error = await response.json();
        alert("Erro no registro: " + error.message);
    }
}

// Função de Login de Usuário
async function login() {
    const username = document.getElementById("login-username").value;
    const password = document.getElementById("login-password").value;

    const response = await fetch(`${urldaapi}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
    });

    if (response.ok) {
        const data = await response.json();
        localStorage.setItem("token", data.token); // Salva o token no localStorage
        alert("Login realizado com sucesso!");
        // Redirecione para uma página protegida, se desejar
        // window.location.href = "/protected.html";
    } else {
        const error = await response.json();
        alert("Erro no login: " + error.message);
    }
}

// Função para obter o token do localStorage
function getToken() {
    return localStorage.getItem("token");
}
