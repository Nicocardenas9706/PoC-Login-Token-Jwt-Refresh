import { ExecutionContext, createParamDecorator } from "@nestjs/common";
//tener en cuenta
export const GetCurrentUserId = createParamDecorator(
    (data: undefined, context: ExecutionContext): number => {
        const request = context.switchToHttp().getRequest()
        return request.user['sub'];
    }
)