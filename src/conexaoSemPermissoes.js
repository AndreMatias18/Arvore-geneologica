import mysql from "mysql"
const conexaoSemPermissoes = mysql.createConnection({
    host: "localhost",
    port: "3306",
    user: "sempermissoes",
    password:"sempermissoes",
    database:"arvoregeneologica"
})
conexaoSemPermissoes.connect()
export default conexaoSemPermissoes

