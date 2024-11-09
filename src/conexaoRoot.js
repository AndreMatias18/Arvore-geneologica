import mysql from "mysql"
const conexaoRoot = mysql.createConnection({
    host: "localhost",
    port: "3306",
    user: "root",
    password:"Andrematias18@",
    database:"arvoregeneologica"
})
conexaoRoot.connect()
export default conexaoRoot

