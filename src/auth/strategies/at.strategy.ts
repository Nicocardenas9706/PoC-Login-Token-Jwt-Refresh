import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { JwtPayload } from "../types/jwtPayload.type";
import { Strategy } from "passport-local";
import { ExtractJwt } from "passport-jwt";



@Injectable()
export class AtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(config: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.get<string>('at_secret'),
    });
  }

  validate(payload: JwtPayload) {
    return payload;
  }
}