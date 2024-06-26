import { Module } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { AuthController } from "./auth.controller";
import { MongooseModule } from "@nestjs/mongoose";
import { User, UserSchema } from "src/schemas/user.schema";
import { JwtModule } from "@nestjs/jwt";


@Module({
    imports: [MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]), JwtModule.register({ secret: 'hard!to-guess_secret' }), JwtModule.register({
        secret: 'secret',
        signOptions: { expiresIn: '5d'}
    })],
    controllers: [AuthController],
    providers: [AuthService]
})

export class AuthModule {}