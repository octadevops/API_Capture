FINANCIAL_CRAWLERS = {
    # Financial Data Specific
    'yfinance': {
        'name': 'yfinance',
        'type': 'Financial Data',
        'description': 'Yahoo Finance data scraper',
        'install': 'pip install yfinance',
        'features': ['stock data', 'historical', 'fundamentals']
    },
    
    'alpha_vantage': {
        'name': 'Alpha Vantage',
        'type': 'API',
        'description': 'Free stock API',
        'install': 'pip install alpha_vantage',
        'features': ['real-time', 'historical', 'technical indicators']
    },
    
    'stocknews': {
        'name': 'StockNews',
        'type': 'News Scraper',
        'description': 'Stock news aggregation',
        'install': 'pip install stocknews',
        'features': ['news scraping', 'sentiment', 'aggregation']
    },
    
    'finviz': {
        'name': 'FinViz',
        'type': 'Screeners',
        'description': 'Stock screeners and data',
        'install': 'pip install finviz',
        'features': ['screener', 'news', 'charts']
    },
    
    'investpy': {
        'name': 'InvestPy',
        'type': 'Financial Data',
        'description': 'Investing.com data scraper',
        'install': 'pip install investpy',
        'features': ['stocks', 'bonds', 'commodities']
    },
    
    'ta': {
        'name': 'Technical Analysis',
        'type': 'Indicators',
        'description': 'Technical analysis library',
        'install': 'pip install ta',
        'features': ['indicators', 'patterns', 'signals']
    },
}