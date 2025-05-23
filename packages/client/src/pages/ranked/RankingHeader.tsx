type RankingHeaderProps = {
	title: string;
	subtitle: string;
};

function RankingHeader({ title, subtitle }: RankingHeaderProps) {
	return (
		<div className="w-full mr-0">
			<h3 className="text-2xl font-bold text-gray-800">{title}</h3>
			<div className="flex justify-between">
				<span className="text-sm text-gray-700">{subtitle}</span>
				<span className="text-xs pr-2 text-gray-700">*초기 자본금: 3천만원</span>
			</div>
		</div>
	);
}

export default RankingHeader;
