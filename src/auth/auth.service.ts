import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { Merchant } from '../merchants/entities/merchant.entity';
import { LoginDto } from './dto/login.dto';

/**
 * Cost factor used for merchant password hashes. Kept in sync with the value
 * used when hashing passwords so the dummy comparison below costs the same.
 */
const PASSWORD_HASH_ROUNDS = 10;

/**
 * Pre-computed bcrypt hash of a random, never-issued password. It is compared
 * against when no merchant matches the login email so that the login endpoint
 * takes the same time whether or not the account exists (no user enumeration
 * via response timing).
 */
const DUMMY_PASSWORD_HASH = bcrypt.hashSync(
  'dupdap-dummy-password-for-constant-time-login',
  PASSWORD_HASH_ROUNDS,
);

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(Merchant)
    private readonly merchantsRepo: Repository<Merchant>,
  ) {}

  /**
   * Verify merchant credentials.
   *
   * Always performs exactly one bcrypt comparison, even when the merchant is
   * not found, so response timing does not reveal whether an email is
   * registered.
   */
  async login(dto: LoginDto): Promise<{ merchant: Merchant }> {
    const merchant = await this.merchantsRepo.findOne({
      where: { email: dto.email },
      select: ['id', 'email', 'passwordHash'],
    });

    const passwordMatches = await bcrypt.compare(
      dto.password,
      merchant?.passwordHash ?? DUMMY_PASSWORD_HASH,
    );

    if (!merchant || !passwordMatches) {
      throw new UnauthorizedException('Invalid email or password');
    }

    return { merchant };
  }
}
