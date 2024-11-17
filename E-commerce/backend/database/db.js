require('dotenv').config()
const mongoose=require("mongoose")

exports.connectToDB=async()=>{
    try {
        await mongoose.connect('mongodb://localhost:27017');
        console.log('connected to DB');
    } catch (error) {
        console.log(error);
    }
}

