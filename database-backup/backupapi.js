import express, { query, response } from "express";
import path from "path"; 
import bodyParser from "body-parser";
import conexaoSemPermissoes from "./conexaoSemPermissoes.js"; // Conexão para usuários sem permissões
import conexaoRoot from "./conexaoRoot.js"; // Conexão para root
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();
const PORT = 3000;

const SECRET_KEY = "TGPSI"; 

// Middleware de Autenticação JWT
function authorizationMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(403).json({ message: "Token não fornecido." });

    const token = authHeader.split(" ")[1];
    try {
        const payload = jwt.verify(token, SECRET_KEY);
        req.user = payload; 
        next();
    } catch (err) {
        res.status(403).json({ message: "Token inválido." });
    }
}

// Middleware para verificar se o usuário é administrador
function adminOnly(req, res, next) {
    if (req.user.isAdmin) return next(); // Apenas administradores podem continuar
    return res.status(403).json({ message: "Permissão negada." });
}

// Middleware
app.use(bodyParser.json()); // Para interpretar requisições JSON
app.use(express.static(path.join(process.cwd(), 'front-end'))); // Serve arquivos da pasta front-end

// Rota principal que serve a página HTML
app.get("/", (req, res) => {
    res.redirect("/registro_login.html"); // Redireciona para a página de login/registro
});

// Rota para Registro de Usuário
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const query = INSERT INTO Users (username, password, is_admin) VALUES (?, ?, FALSE); // FALSE para usuário comum
    conexaoSemPermissoes.query(query, [username, hashedPassword], (err, result) => {
        if (err) {
            console.error("Erro ao registrar usuário:", err);
            return res.status(500).json({ message: "Erro ao registrar usuário." });
        }
        res.status(201).json({ message: "Usuário registrado com sucesso." });
    });
});

// Rota para Login de Usuário
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const query = SELECT * FROM Users WHERE username = ?;

    conexaoRoot.query(query, [username], async (err, results) => {
        if (err || results.length === 0) {
            return res.status(401).json({ message: "Usuário ou senha inválidos." });
        }

        const user = results[0];
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ message: "Usuário ou senha inválidos." });
        }

        const token = jwt.sign({ id: user.id, username: user.username, isAdmin: user.is_admin }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ token });
    });
});

// Rota para adicionar uma nova pessoa (apenas administradores)
app.post('/pessoas', authorizationMiddleware, adminOnly, (req, res) => {
    const { nome, data_nascimento, data_falecimento, sexo, local_nascimento, local_falecimento, id_mae, id_pai } = req.body;
    
    // Verifica se todos os campos necessários estão presentes
    if (!nome || !data_nascimento || !sexo) {
        return res.status(400).send("Todos os campos obrigatórios devem ser preenchidos.");
    }

    const query = INSERT INTO Pessoas (Nome, Data_Nascimento, Data_Falecimento, Sexo, Local_de_Nascimento, Local_de_Falecimento, ID_Mae, ID_Pai)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?);
    conexaoRoot.query(query, [nome, data_nascimento, data_falecimento, sexo, local_nascimento, local_falecimento, id_mae, id_pai], (err, result) => {
        if (err) {
            console.error("Erro ao adicionar pessoa:", err);
            res.status(500).send("Erro ao adicionar pessoa.");
        } else {
            res.status(201).send("Pessoa adicionada com sucesso.");
        }
    });
});



// Rota para buscar todas as pessoas (permitido para todos os usuários)
app.get('/pessoa', (req, res) => {
    const ids = req.query.ids.split(','); // Extrai os IDs passados como query string
    const query = 'SELECT ID_Pessoa, Nome FROM Pessoas WHERE ID_Pessoa IN (?)';

    conexaoSemPermissoes.query(query, [ids], (err, results) => {
        if (err) {
            console.error("Erro ao buscar pessoas:", err);
            res.status(500).send("Erro ao buscar pessoas.");
        } else if (results.length > 0) {
            // Cria um objeto onde a chave é o ID_Pessoa e o valor é o nome da pessoa
            const pessoas = {};
            results.forEach(result => {
                pessoas[result.ID_Pessoa] = { Nome: result.Nome };
            });
            res.json(pessoas);
        } else {
            res.status(404).send("Pessoas não encontradas.");
        }
    });
});

// Rota para buscar pessoa por ID
app.get('/pessoa/:id', (req, res) => {
    const idPessoa = req.params.id;
    const query = 'SELECT Nome FROM Pessoas WHERE ID_Pessoa = ?';

    conexaoSemPermissoes.query(query, [idPessoa], (err, result) => {
        if (err) {
            console.error("Erro ao buscar pessoa:", err);
            res.status(500).send("Erro ao buscar pessoa.");
        } else if (result.length > 0) {
            res.json(result[0]);  // Retorna o nome da pessoa
        } else {
            res.status(404).send("Pessoa não encontrada.");
        }
    });
});

// Rota para adicionar morada (requer root)
app.post('/morada', authorizationMiddleware, adminOnly, (req, res) => {
    const { id_pessoa, morada, cidade, freguesia, pais, datainicio, datafim } = req.body;
    const query = INSERT INTO Endereco (ID_Pessoa, morada, Cidade, freguesia, Pais, Data_Inicio, Data_Fim)
                   VALUES (?, ?, ?, ?, ?, ?, ?);
    conexaoRoot.query(query, [id_pessoa, morada, cidade, freguesia, pais, datainicio, datafim], (err, result) => {
        if (err) {
            console.error("Erro ao adicionar morada:", err);
            res.status(500).send("Erro ao adicionar morada.");
        } else {
            res.status(201).send("Morada adicionada com sucesso.");
        }
    });
});

// Rota para adicionar relacionamento (requer root)
app.post('/relacionamento', authorizationMiddleware, adminOnly, (req, res) => {
    const { id_pessoa1, id_pessoa2, tipoderelacionamento, datadeinicio, datadefim } = req.body;
    const query = INSERT INTO Relacionamentos (ID_Pessoa_1, ID_Pessoa_2, Tipo_de_Relacionamento, Data_Inicio, Data_Fim)
                   VALUES (?, ?, ?, ?, ?);
    conexaoRoot.query(query, [id_pessoa1, id_pessoa2, tipoderelacionamento, datadeinicio, datadefim], (err, result) => {
        if (err) {
            console.error("Erro ao adicionar relacionamento:", err);
            res.status(500).send("Erro ao adicionar relacionamento.");
        } else {
            res.status(201).send("Relacionamento adicionado com sucesso.");
        }
    });
});

// Rota para adicionar evento (requer root)
app.post('/evento', authorizationMiddleware, adminOnly, (req, res) => {
    const { e_id_pessoa1, tipodeevento, dataevento, descricao, localevento } = req.body;
    const query = INSERT INTO Eventos (ID_Pessoa, Tipo_Evento, Data_Evento, Descricao, Local_Evento)
                   VALUES (?, ?, ?, ?, ?);
    conexaoRoot.query(query, [e_id_pessoa1, tipodeevento, dataevento, descricao, localevento], (err, result) => {
        if (err) {
            console.error("Erro ao adicionar Evento:", err);
            res.status(500).send("Erro ao adicionar Evento.");
        } else {
            res.status(201).send("Evento adicionado com sucesso.");
        }
    });
});

// Rota para consultar moradas
app.get("/consultarmoradas", (req, res) => {
    const idpessoa_c_m = req.query.id; // Obtém o ID da query string
    const query = "SELECT * FROM Endereco WHERE ID_Pessoa = ?";
    
    conexaoSemPermissoes.query(query, [idpessoa_c_m], (err, result) => {
        if (err) {
            console.error("Erro ao Consultar Morada:", err);
            res.status(500).send("Erro ao Consultar Morada.");
        } else {
            if (result.length > 0) {
                res.status(200).json(result); // Retorna os resultados encontrados
            } else {
                res.status(404).send("Nenhuma morada encontrada."); // Retorna 404 se não encontrar resultados
            }
        }
    });
});

// Rota para consultar eventos
app.get("/consultareventos", (req, res) => {
    const idpessoa_c_m = req.query.id; // Obtém o ID da query string
    const query = "SELECT * FROM Eventos WHERE ID_Pessoa = ?";
    
    conexaoSemPermissoes.query(query, [idpessoa_c_m], (err, result) => {
        if (err) {
            console.error("Erro ao Consultar Evento:", err);
            res.status(500).send("Erro ao Consultar Evento.");
        } else {
            if (result.length > 0) {
                res.status(200).json(result);
            } else {
                res.status(404).send("Nenhuma Evento Encontrada."); 
            }
        }
    });
});

// Rota para consultar pessoa
app.get("/consultarpessoa", (req, res) => {
    const idpessoa_c_p = req.query.id;
    const query = "SELECT * FROM Pessoas WHERE ID_Pessoa = ?";
    
    conexaoSemPermissoes.query(query, [idpessoa_c_p], (err, result) => {
        if (err) {
            console.error("Erro ao Consultar Pessoa", err);
            res.status(500).send("Erro ao Consultar Pessoa.");
        } else {
            if (result.length > 0) {
                res.status(200).json(result);
            } else {
                res.status(404).send("Nenhuma Pessoa Encontrada.");
            }
        }
    });
});

// Rota para consultar relacionamento
app.get('/consultarrelacionamento', authorizationMiddleware, (req, res) => {
    const { id_pessoa1, id_pessoa2 } = req.query;

    const query = SELECT Tipo_de_Relacionamento, Data_Inicio, Data_Fim 
                   FROM Relacionamentos 
                   WHERE (ID_Pessoa_1 = ? AND ID_Pessoa_2 = ?) 
                      OR (ID_Pessoa_1 = ? AND ID_Pessoa_2 = ?);

    conexaoSemPermissoes.query(query, [id_pessoa1, id_pessoa2, id_pessoa2, id_pessoa1], (err, results) => {
        if (err) {
            console.error("Erro ao buscar relacionamento:", err);
            return res.status(500).json({ error: "Erro ao buscar relacionamento." });
        } 
        
        if (results.length > 0) {
            return res.json(results);
        } else {
            return res.status(404).json({ message: "Nenhum relacionamento encontrado." });
        }
    });
});


app.delete('/apagarpessoas', authorizationMiddleware, adminOnly, async (req, res) => {
    const idPessoa = req.query.id;

    if (!idPessoa) {
        return res.status(400).send("ID da pessoa não fornecido.");
    }

    console.log(`a apagar pessoa com ID: ${idPessoa}`);

    try {
        await conexaoRoot.query('DELETE FROM Eventos WHERE ID_Pessoa = ?', [idPessoa]);
        await conexaoRoot.query('DELETE FROM Relacionamentos WHERE ID_Pessoa_1 = ? OR ID_Pessoa_2 = ?', [idPessoa, idPessoa]);
        await conexaoRoot.query('DELETE FROM Endereco WHERE ID_Pessoa = ?', [idPessoa]);
        
        const result = await conexaoRoot.query('DELETE FROM Pessoas WHERE ID_Pessoa = ?', [idPessoa]);

        console.log(result);
        if (result.affectedRows === 0) {
            return res.status(404).send("Pessoa não encontrada.");
        }

        res.send("Pessoa apagada com sucesso.");
    } catch (err) {
        console.error("Erro ao apagar pessoa:", err);
        return res.status(500).send(err.message);
    }
});

// Rota para apagar morada (requer root)
app.delete("/apagarmoradas", authorizationMiddleware, adminOnly, (req,res) => {
    const idmorada = req.query.id;
    conexaoRoot.query('DELETE FROM Endereco WHERE ID_Endereco = ?', [idmorada], (err, result) => {
        if (err) {
            console.error("Erro ao apagar morada:", err);
            res.status(500).send("Erro ao apagar morada.");
        } else {
            res.status(204).send("Morada apagada com sucesso."); // 204 No Content
        }
    });
});


