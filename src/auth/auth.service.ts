import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as bcrypt from 'bcrypt'
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

@Injectable()
export class AuthService {

    constructor(private prisma: PrismaService,
        private jwtService: JwtService,
        private config: ConfigService,
        ){}
    

    async signupLocal(dto: AuthDto): Promise <Tokens>{
        const hash = await this.hashData(dto.password);

        const newUser = await this.prisma.user.create({
            data:{
                email: dto.email,
                hash,
            }
        })
        .catch((error) => {
            if (error instanceof PrismaClientKnownRequestError) {
              if (error.code === 'P2002') {
                throw new ForbiddenException('Credentials incorrect');
              }
            }
            throw error;
          });
    
        const tokens = await this.getTokens(newUser.id, newUser.email)
        await this.updateRtHash(newUser.id, tokens.refresh_token);

        return tokens;
    }

    async signinLocal(dto: AuthDto): Promise<Tokens> {
        const user = await this.prisma.user.findUnique({
          where: {
            email: dto.email,
          },
        });

        if(!user) throw new ForbiddenException("Access denied");

        const passwordMatches = await bcrypt.compare(dto.password, user.hash);
        if(!passwordMatches) throw new ForbiddenException("Access denied");

        const tokens = await this.getTokens(user.id, user.email);
        await this.updateRtHash(user.id, tokens.refresh_token);
        return tokens;
    }
    async logout(userId: number){
        await this.prisma.user.updateMany({
            where: {
                id: userId,
                hasshedRt: {
                    not: null,
                },
            },
            data: {
                hasshedRt: null
            }
        });
        return true;
    }
    async refreshTokens(userId: number, rt: string): Promise<Tokens>{
        const user = await this.prisma.user.findUnique({
            where: {
                id: userId
            }
        });
        if(!user) throw new ForbiddenException("Access denied");

        const rtMatches = bcrypt.compare(rt, user.hasshedRt);
        if(!rtMatches) throw new ForbiddenException("Access denied");

        const tokens = await this.getTokens(user.id, user.email);
        await this.updateRtHash(user.id, tokens.refresh_token);
        return tokens;
    }

    async updateRtHash(userId: number, rt: string): Promise<void>{
        const hash = await this.hashData(rt)
        await this.prisma.user.update({
            where: {
                id: userId
            },
            data: {
                hasshedRt: hash,
            },
        });
    }

    hashData(data: string){
        return bcrypt.hash(data, 10);
    }

    async getTokens(userId: number, email: string): Promise <Tokens>{
        const [at, rt] = await Promise.all([
            this.jwtService.signAsync(
            {
                sub: userId,
                email,
            },
            {
                secret: 'at-secret',
                expiresIn: 60*15,
            },
        ),
            this.jwtService.signAsync(
                {
                    sub: userId,
                    email,
                },
                {
                secret: 'rt-secret',
                expiresIn: 60*15,
                },
            ),
        ]);

        return {
            access_token: at,
            refresh_token: rt,
        }
    }

}
