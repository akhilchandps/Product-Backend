const multer = require('multer')
const { DATE } = require('sequelize')

const storage = multer.diskStorage({
    destination:(req,file,callback)=>{
        callback(null, './uploads')
    },

    // set Image name

    filename:(req,file,callback)=>{

        const filename = `image ${DATE.now()} ${file.originalname}`
        callback(null, filename)

    }

})
 const fileFilter = (req,file,callback)=>{

    if(file.mimetype === "image/png" || file.mimetype === "image/jpeg" || file.mimetype === "image/jpg"  ){

        callback(null,filename)
    }else{
        callback(null,false)
        return callback(new Error("please upload following image extension(png,jpg,jpeg only...."))

    }
 }


 const multerConfig = multer({
    storage,fileFilter
 })

 module.exports=multerConfig
