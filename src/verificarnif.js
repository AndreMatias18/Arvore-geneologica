import mongoose from 'mongoose';
const pessoaSchema = new mongoose.Schema({
    nome: String,
    nif: { type: String, unique: true },
    data_nascimento: Date,
    data_falecimento: Date,
    sexo: String,
    local_nascimento: String,
    local_falecimento: String,
    nif_mae: String,
    nif_pai: String
});
export default mongoose.model('Pessoa', pessoaSchema);
