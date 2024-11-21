import { Change, CoinTicker } from '@/types/ticker';
import colorClasses from '@/constants/priceColor';
import { AccountCoin } from '@/types/account';
import PORTFOLIO_EVALUATOR from '@/utility/portfolioEvaluator';

type BalanceCoinProps = {
	coin: AccountCoin;
	sseData: CoinTicker;
};

function BalanceCoin({ coin, sseData }: BalanceCoinProps) {
	const {
		evaluatePerPrice,
		calculateProfitPrice,
		calculateProfitRate,
		getChangeStatus,
	} = PORTFOLIO_EVALUATOR;

	const averagePrice = (coin.price / coin.quantity).toFixed(2);

	const evaluationPerPrice = evaluatePerPrice(
		coin.quantity,
		sseData.trade_price,
	);

	const profitPrice = calculateProfitPrice(evaluationPerPrice, coin.price);

	const profitRate = calculateProfitRate(evaluationPerPrice, coin.price);

	const change: Change = getChangeStatus(profitRate);

	return (
		<div className="flex border-b border-solid border-gray-300">
			<div className="flex-[1]  pt-3 px-3">
				<div className="flex items-center gap-3">
					<img className="w-7 h-7" src={coin.img_url} />
					<div className="flex flex-col">
						<p className="font-semibold">{coin.koreanName}</p>
						<p className="text-gray-700 text-xs">{coin.market}</p>
					</div>
				</div>
			</div>
			<div className="flex-[1] p-3 text-end">
				<span className="text-base ">{coin.quantity.toLocaleString()}</span>
				<span className="text-xs ml-1 text-gray-500">{coin.market}</span>
			</div>
			<div className="flex-[1] p-3 text-end">
				<span className="text-base">{averagePrice}</span>
				<span className="text-xs ml-1 text-gray-500">KRW</span>
			</div>
			<div className="flex-[1] p-3 text-end">
				<span className="text-base">{coin.price.toLocaleString()}</span>
				<span className="text-xs ml-1 text-gray-500">KRW</span>
			</div>
			<div className="flex-[1] p-3 text-end">
				<span className="text-base font-bold">
					{evaluationPerPrice.toLocaleString()}
				</span>
				<span className="text-xs ml-1 text-gray-500">KRW</span>
			</div>
			<div className="flex-[1] p-3">
				<div className="flex flex-col text-end mr-12">
					<div className="">
						<span className={`text-base ${colorClasses[change]}`}>
							{profitRate.toFixed(2)}
						</span>
						<span className="text-xs ml-1 text-gray-500">%</span>
					</div>
					<div className="">
						<span className={`text-base ${colorClasses[change]}`}>
							{profitPrice.toLocaleString()}
						</span>
						<span className="text-xs ml-1 text-gray-500">KRW</span>
					</div>
				</div>
			</div>
		</div>
	);
}

export default BalanceCoin;
