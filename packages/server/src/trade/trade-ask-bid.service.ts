import { Injectable, Logger } from '@nestjs/common';
import { AccountRepository } from '@src/account/account.repository';
import { AssetRepository } from '@src/asset/asset.repository';
import { DataSource, QueryRunner } from 'typeorm';
import { TradeRepository } from './trade.repository';
import { UserRepository } from '@src/auth/user.repository';
import { TradeHistoryRepository } from '@src/trade-history/trade-history.repository';
import { CoinDataUpdaterService } from '@src/upbit/coin-data-updater.service';
import { CoinPriceDto, TradeData } from './dtos/trade.interface';
import { formatQuantity, isMinimumQuantity } from './helpers/trade.helper';
import { TradeRedisRepository } from '@src/redis/trade-redis.repository';
import { TRADE_TYPES } from './constants/trade.constants';

@Injectable()
export class TradeAskBidService {
  private readonly logger = new Logger(TradeAskBidService.name);
  constructor(
    protected readonly dataSource: DataSource,
    protected readonly accountRepository: AccountRepository,
    protected readonly assetRepository: AssetRepository,
    protected readonly tradeRepository: TradeRepository,
    protected readonly userRepository: UserRepository,
    protected readonly tradeHistoryRepository: TradeHistoryRepository,
    protected readonly coinDataUpdaterService: CoinDataUpdaterService,
    protected readonly redisRepository: TradeRedisRepository,
  ) {}
  protected async processPendingTrades(
    tradeType: TRADE_TYPES.SELL | TRADE_TYPES.BUY,
    handler: (tradeDto: TradeData) => Promise<void>,
  ) {
    try {
      const coinLatestInfo = this.coinDataUpdaterService.getCoinLatestInfo();
      if (coinLatestInfo.size === 0) return;

      const coinPrices = this.buildCoinPrices(coinLatestInfo);

      const availableTrades = await this.redisRepository.findMatchingTrades(
        tradeType,
        coinPrices,
      );

      for (const trade of availableTrades) {
        try{
        const tradeDto = this.buildTradeDto(trade, coinLatestInfo, tradeType);
        this.logger.debug(`처리 중인 거래: tradeId=${tradeDto.tradeId}`);
        await handler(tradeDto);
        } catch (err) {
          this.logger.error(
            `미체결 거래 처리 중 오류 발생: trade=${JSON.stringify(trade)}, error=${err.message}`,
            err.stack,
          );
        }
      }
    } catch (error) {
      this.logger.error(
        `미체결 거래 처리 전반적 오류: tradeType=${tradeType}, error=${error.message}`,
        error.stack,
      );
    } finally {
      this.logger.log(`${tradeType} 미체결 거래 처리 완료`);
    }
  }
  private buildCoinPrices(coinLatestInfo: Map<string, any>): CoinPriceDto[] {
    const prices: CoinPriceDto[] = [];
    coinLatestInfo.forEach((value, key) => {
      const [give, receive] = key.split('-');
      prices.push({
        give: give,
        receive: receive,
        price: value.trade_price,
      });
    });
    return prices;
  }

  private buildTradeDto(
    trade: any,
    coinLatestInfo: Map<string, any>,
    tradeType: TRADE_TYPES.BUY | TRADE_TYPES.SELL,
  ): TradeData {
    const [baseMarket, targetMarket] =
      tradeType === TRADE_TYPES.BUY
        ? [trade.assetName, trade.tradeCurrency]
        : [trade.tradeCurrency, trade.assetName];

    const krw = coinLatestInfo.get(`KRW-${baseMarket}`).trade_price;
    const another = coinLatestInfo.get(
      `${targetMarket}-${baseMarket}`,
    ).trade_price;

    return {
      userId: trade.userId,
      typeGiven: trade.tradeCurrency,
      typeReceived: trade.assetName,
      receivedPrice: trade.price,
      receivedAmount: trade.quantity,
      tradeId: trade.tradeId,
      krw: formatQuantity(krw / another),
    };
  }

  protected async executeTransaction<T>(
    callback: (queryRunner: QueryRunner) => Promise<T>,
  ): Promise<T> {
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction('READ COMMITTED');

    try {
      const result = await callback(queryRunner);
      await queryRunner.commitTransaction();
      return result;
    } catch (error) {
      await queryRunner.rollbackTransaction();
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  async updateTradeData(
    tradeData: any,
    buyData: any,
    queryRunner: QueryRunner,
  ): Promise<number> {
    tradeData.quantity = formatQuantity(tradeData.quantity - buyData.quantity);
    if (isMinimumQuantity(tradeData.quantity)) {
      await this.tradeRepository.deleteTrade(tradeData.tradeId, queryRunner);
      await queryRunner.commitTransaction();
      await this.redisRepository.deleteTrade(tradeData);
    } else {
      await this.tradeRepository.updateTradeQuantity(tradeData, queryRunner);
    }

    return tradeData.quantity;
  }
}
