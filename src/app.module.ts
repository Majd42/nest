import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthModule } from './auth/auth.module';


@Module({
  imports: [MongooseModule.forRoot('mongodb+srv://Majd:ms1223330@cluster0.tsjxcdk.mongodb.net/nest?retryWrites=true&w=majority&appName=Cluster0'), AuthModule],
  controllers: [],
  providers: [],
  
})
export class AppModule {}
