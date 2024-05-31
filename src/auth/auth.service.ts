import { HttpException, Injectable } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import { User } from "src/schemas/user.schema";
import { AuthDto, RegisterDto } from "./dto";
import * as bcrypt from 'bcrypt';
import { JwtService } from "@nestjs/jwt";

@Injectable()
export class AuthService {

    constructor(@InjectModel(User.name) private userModel: Model<User>, private readonly jwtService: JwtService) {}

    async login(authDto: AuthDto) {
        
        const findUser = await this.userModel.findOne({
            email: authDto.email
        })
    
        if(!findUser) return null

        const checkPassword = await bcrypt.compare(authDto.password, findUser.password)

        if (!checkPassword) throw new HttpException("invalid credentials", 400)

        const {password, ...user} = findUser

  
        if(!user) throw new HttpException("invalid credentials", 400)
        return this.jwtService.sign(user)
        
    }





    async register(registerDto: RegisterDto) {

        try {
            const hash = await bcrypt.hash(registerDto.password, 10)
        
        
            const user = await this.userModel.create({
                name: registerDto.name,
                password: hash,
                email: registerDto.email,
                
            })

            return { user }
    
        } catch (error) {
            return {
                error
            }
        }

    }
}