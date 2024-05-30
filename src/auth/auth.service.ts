import { Injectable } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import { User } from "src/schemas/user.schema";
import { AuthDto, RegisterDto } from "./dto";
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {

    constructor(@InjectModel(User.name) private userModel: Model<User>) {}

    login(authDto: AuthDto) {
        console.log(authDto)
        return("hi")
    }

    async register(registerDto: RegisterDto) {

        try {
            const hash = await bcrypt.hash(registerDto.password, 10)
        
        
            const user = await this.userModel.create({
                name: registerDto.name,
                password: hash,
                emaiL: registerDto.email,
                
            })

            return { user }
    
        } catch (error) {
            return {
                error
            }
        }

    }
}