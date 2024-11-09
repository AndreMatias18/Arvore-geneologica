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

    const query = "INSERT INTO Users (username, password, is_admin) VALUES (?, ?, FALSE);"; // FALSE para usuário comum
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
    const query = "SELECT * FROM Users WHERE username = ?";

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
    const { nif ,nome, data_nascimento, data_falecimento, sexo, local_nascimento, local_falecimento, nif_mae, nif_pai } = req.body;
    
    // Verifica se todos os campos necessários estão presentes
    if (!nome || !data_nascimento ||!nif|| !sexo) {
        return res.status(400).send("Todos os campos obrigatórios devem ser preenchidos.");
    }

    const query = "INSERT INTO Pessoas (nif , Nome,  Data_Nascimento, Data_Falecimento, Sexo, Local_de_Nascimento, Local_de_Falecimento, NIF_Mae, NIF_Pai) VALUES (?, ?, ?, ?, ?, ?, ?, ?,?);";
    conexaoRoot.query(query, [nif ,nome,  data_nascimento, data_falecimento, sexo, local_nascimento, local_falecimento, nif_mae, nif_pai], (err, result) => {
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
    const nifPessoa = req.query.nif;

    if (!nifPessoa) {
        return res.status(400).send("NIF é obrigatório.");
    }

    const query = "SELECT NIF, Nome FROM Pessoas WHERE NIF = ?";
    
    conexaoSemPermissoes.query(query, [nifPessoa], (err, results) => {
        if (err) {
            console.error("Erro ao buscar pessoa:", err);
            return res.status(500).send("Erro ao buscar pessoa.");
        }

        // Verificando a resposta da consulta
        console.log("Resultado da consulta:", results);

        if (results.length > 0) {
            // Envia o primeiro resultado, que deve ser o nome da pessoa
            res.json(results[0]); // Retorna o primeiro resultado da consulta
        } else {
            res.status(404).send("Pessoa não encontrada.");
        }
    });
});


// Rota para buscar pessoa por NIF
app.get('/pessoa/:nif', (req, res) => {
    const nifPessoa = req.params.nif;
    const query = "SELECT Nome FROM Pessoas WHERE NIF = ?";

    conexaoSemPermissoes.query(query, [nifPessoa], (err, result) => {
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

app.get('/consultarpessoa/:nif', (req, res) => {
    const nifPessoa = req.params.nif;

    const query = `
        SELECT p.Nome, p.Data_Nascimento, p.Data_Falecimento, p.Sexo, 
               p.Local_de_Nascimento, p.Local_de_Falecimento, 
               m.Nome AS Nome_Mae, f.Nome AS Nome_Pai
        FROM Pessoas p
        LEFT JOIN Pessoas m ON p.NIF_Mae = m.NIF
        LEFT JOIN Pessoas f ON p.NIF_Pai = f.NIF
        WHERE p.NIF = ?
    `;

    conexaoSemPermissoes.query(query, [nifPessoa], (err, result) => {
        if (err) {
            console.error("Erro ao buscar pessoa:", err);
            res.status(500).send("Erro ao buscar pessoa.");
        } else if (result.length > 0) {
            res.json(result[0]);  // Retorna todas as informações da pessoa, incluindo os nomes dos pais
        } else {
            res.status(404).send("Pessoa não encontrada.");
        }
    });
});


// Rota para adicionar morada (requer root)
app.post('/morada', authorizationMiddleware, adminOnly, (req, res) => {
    const { nif_pessoa, morada, cidade, freguesia, pais, datainicio, datafim } = req.body;

    console.log("Dados recebidos para adicionar morada:", req.body);  // Log dos dados recebidos
    
    // Verificar se o NIF existe na base de dados
    const checkPersonQuery = "SELECT * FROM Pessoas WHERE NIF = ?";

    conexaoRoot.query(checkPersonQuery, [nif_pessoa], (err, result) => {
        if (err) {
            console.error("Erro ao verificar pessoa:", err);  // Log do erro
            return res.status(500).send("Erro ao verificar pessoa.");
        }

        console.log("Resultado da busca pelo NIF:", result);  // Log do resultado da consulta

        if (result.length === 0) {
            return res.status(404).send("Pessoa não encontrada.");
        }

        // Se a pessoa existir, prosseguir com a inserção da morada
        const query = "INSERT INTO endereco (NIF_Pessoa, morada, Cidade, freguesia, Pais, Data_Inicio, Data_Fim) VALUES (?, ?, ?, ?, ?, ?, ?);";
        
        conexaoRoot.query(query, [nif_pessoa, morada, cidade, freguesia, pais, datainicio, datafim], (err, result) => {
            if (err) {
                console.error("Erro ao adicionar morada:", err);  // Log do erro
                return res.status(500).send("Erro ao adicionar morada.2");
            } else {
                console.log("Morada adicionada com sucesso:", result);  // Log do sucesso
                return res.status(201).send("Morada adicionada com sucesso.");
            }
        });
    });
});



// Rota para adicionar relacionamento (requer root)
app.post('/relacionamento', authorizationMiddleware, adminOnly, (req, res) => {
    const { nif_pessoa1, nif_pessoa2, tipoderelacionamento, datadeinicio, datadefim } = req.body;
    const query = "INSERT INTO Relacionamentos (NIF_Pessoa_1, NIF_Pessoa_2, Tipo_de_Relacionamento, Data_Inicio, Data_Fim) VALUES (?, ?, ?, ?, ?);";
    conexaoRoot.query(query, [nif_pessoa1, nif_pessoa2, tipoderelacionamento, datadeinicio, datadefim], (err, result) => {
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
    const { nif_pessoa, tipodeevento, dataevento, descricao, localevento } = req.body;
    const query = "INSERT INTO Eventos (NIF_Pessoa, Tipo_Evento, Data_Evento, Descricao, Local_Evento) VALUES (?, ?, ?, ?, ?);";
    conexaoRoot.query(query, [nif_pessoa, tipodeevento, dataevento, descricao, localevento], (err, result) => {
        if (err) {
            console.error("Erro ao adicionar Evento:", err);
            res.status(500).send("Erro ao adicionar Evento.");
        } else {
            res.status(201).send("Evento adicionado com sucesso.");
        }
    });
});

// Rota para consultar todos os eventos de uma pessoa, incluindo o nome
app.get('/eventos', (req, res) => {
    const nifPessoa = req.query.nif;
    const query = `
        SELECT Eventos.*, Pessoas.Nome
        FROM Eventos
        JOIN Pessoas ON Eventos.NIF_Pessoa = Pessoas.NIF
        WHERE Eventos.NIF_Pessoa = ?;
    `;

    conexaoSemPermissoes.query(query, [nifPessoa], (err, results) => {
        if (err) {
            console.error("Erro ao buscar eventos:", err);
            res.status(500).send("Erro ao buscar eventos.");
        } else if (results.length > 0) {
            res.json(results);
        } else {
            res.status(404).send("Nenhum evento encontrado.");
        }
    });
});


app.delete('/pessoa/:nif', authorizationMiddleware, adminOnly, async (req, res) => {
    const nifPessoa = req.params.nif;

    try {
        
        await new Promise((resolve, reject) => {
            conexaoRoot.query('DELETE FROM Endereco WHERE NIF_Pessoa = ?', [nifPessoa], (err, result) => {
                if (err) {
                    console.error("Erro ao excluir endereços:", err);
                    return reject(err);
                }
                resolve(result);
            });
        });

        
        await new Promise((resolve, reject) => {
            conexaoRoot.query('DELETE FROM Relacionamentos WHERE NIF_Pessoa_1 = ? OR NIF_Pessoa_2 = ?', [nifPessoa, nifPessoa], (err, result) => {
                if (err) {
                    console.error("Erro ao excluir relacionamentos:", err);
                    return reject(err);
                }
                resolve(result);
            });
        });

        
        await new Promise((resolve, reject) => {
            conexaoRoot.query('DELETE FROM Eventos WHERE NIF_Pessoa = ?', [nifPessoa], (err, result) => {
                if (err) {
                    console.error("Erro ao excluir eventos:", err);
                    return reject(err);
                }
                resolve(result);
            });
        });


        await new Promise((resolve, reject) => {
            conexaoRoot.query('DELETE FROM Pessoas WHERE NIF = ?', [nifPessoa], (err, result) => {
                if (err) {
                    console.error("Erro ao excluir pessoa:", err);
                    return reject(err);
                }
                if (result.affectedRows === 0) {
                    return res.status(404).send("Pessoa não encontrada.");
                }
                resolve(result);
            });
        });

        res.status(200).send("Pessoa excluída com sucesso.");
    } catch (error) {
        res.status(500).send("Erro ao excluir pessoa e dados relacionados.");
    }
});


app.get('/relacionamento', (req, res) => {
    const nifPessoa = req.query.nif; // Recebe o NIF pela query string
    const query = "SELECT * FROM Relacionamentos WHERE NIF_Pessoa_1 = ? OR NIF_Pessoa_2 = ?";

    conexaoSemPermissoes.query(query, [nifPessoa, nifPessoa], (err, results) => {
        if (err) {
            console.error("Erro ao buscar relacionamentos:", err);
            res.status(500).send("Erro ao buscar relacionamentos.");
        } else if (results.length > 0) {
            res.json(results);  // Retorna todos os relacionamentos associados ao NIF
        } else {
            res.status(404).send("Nenhum relacionamento encontrado.");
        }
    });
});



// Rota para buscar todas as moradas de uma pessoa
app.get('/morada', (req, res) => {
    const nifPessoa = req.query.nif; // Recebe o NIF pela query string
    const query = "SELECT * FROM Endereco WHERE NIF_Pessoa = ?";

    conexaoSemPermissoes.query(query, [nifPessoa], (err, results) => {
        if (err) {
            console.error("Erro ao buscar moradas:", err);
            res.status(500).send("Erro ao buscar moradas.");
        } else if (results.length > 0) {
            res.json(results);  // Retorna todas as moradas associadas ao NIF
        } else {
            res.status(404).send("Nenhuma morada encontrada.");
        }
    });
});




// Rota para apagar uma morada específica pelo ID com autenticação e autorização
app.delete('/morada/:id', authorizationMiddleware, adminOnly, async (req, res) => {
    const idMorada = req.params.id; // Corrigido para pegar o parâmetro da URL

    if (!idMorada) {
        return res.status(400).send("O ID da morada é obrigatório.");
    }

    try {
        // Executa a query para apagar a morada
        await conexaoRoot.query("DELETE FROM Endereco WHERE ID_Endereco = ?", [idMorada]);
        res.status(200).send("Morada apagada com sucesso.");
    } catch (err) {
        console.error("Erro ao apagar a morada:", err);
        res.status(500).send("Erro ao apagar a morada.");
    }
});

app.delete('/relacionamento/:id', authorizationMiddleware, adminOnly, async (req, res) => {
    const idRelacionamento = req.params.id; // Alterei o nome para corresponder ao nome correto do parâmetro

    if (!idRelacionamento) {
        return res.status(400).send("O ID do relacionamento é obrigatório.");
    }

    try {
        await conexaoRoot.query("DELETE FROM Relacionamentos WHERE ID_Relacionamento = ?", [idRelacionamento]);
        res.status(200).send("Relacionamento apagado com sucesso.");
    } catch (err) {
        console.error("Erro ao apagar o Relacionamento:", err);
        res.status(500).send("Erro ao apagar o Relacionamento.");
    }
});

// Endpoint para apagar evento pelo ID
app.delete('/evento/:id', authorizationMiddleware, adminOnly, async (req, res) => {
    const idEvento = req.params.id;

    if (!idEvento) {
        return res.status(400).send("O ID do evento é obrigatório.");
    }

    try {
        await conexaoRoot.query("DELETE FROM Eventos WHERE ID_Evento = ?", [idEvento]);

        res.status(200).send("Evento apagado com sucesso.");
    } catch (err) {
        console.error("Erro ao apagar o evento:", err);
        res.status(500).send("Erro ao apagar o evento.");
    }
});



app.listen(PORT, () => {
    console.log(`Servidor rodando na porta http://localhost:${PORT}`);
});
