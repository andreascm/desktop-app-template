import React, { Component } from 'react'

export default class NavigationBar extends Component {
	static defaultProps = {
		initialSelectedIndex: 0
	}

	menu = {
		0: '',
		1: 'sell',
		2: 'buy',
		3: 'stock',
		6: 'bill',
		4: 'login',
		5: 'database',
	}

	goTo = (section) => {
		const url = {
			index: 	'/',
			sell: 	'/sell',
			buy: 	'/buy',
			stock: 	'/stock',
			bill: 	'/bill',
			login:  '/logout',
			database: 'http://localhost:5984/_utils/#_all_dbs'
		}

		if (url[section]) {
			return () => {
				window.location.href = url[section]
			}
		} else {
			return () => {
				console.error('Unknown section ' + section)
			}
		}
	}

	highlight = (menu) => {
		$('#' + menu + 'ButtonText').css('color', grey)
	}

	unhighlight = (menu) => {
		$('#' + menu + 'ButtonText').css('color', 'white')
		this.highlightSelectedIndex()
	}

	hoverSellOver 		= () => { this.highlight('sell') }
	hoverSellOut 		= () => { this.unhighlight('sell') }
	hoverBuyOver 		= () => { this.highlight('buy') }
	hoverBuyOut 		= () => { this.unhighlight('buy') }
	hoverStockOver 		= () => { this.highlight('stock') }
	hoverStockOut 		= () => { this.unhighlight('stock') }
	hoverBillOver 		= () => { this.highlight('bill') }
	hoverBillOut 		= () => { this.unhighlight('bill') }
	hoverLoginOver 		= () => { this.highlight('login') }
	hoverLoginOut 		= () => { this.unhighlight('login') }
	hoverDatabaseOver 	= () => { this.highlight('database') }
	hoverDatabaseOut	= () => { this.unhighlight('database') }

	highlightSelectedIndex = () => {
		var index = this.props.initialSelectedIndex ? this.props.initialSelectedIndex : 0
		$('#' + this.menu[index] + 'Button').css('border-bottom', '2px solid ' + red)
		$('#' + this.menu[index] + 'ButtonText').css('color', red)
	}

	componentDidMount = () => {
		this.highlightSelectedIndex()
	}

	render = () => {
		var buttonStyle = {
				display: 'inline-block',
				textAlign: 'center',
				padding: '0px 0px 8px 16px',
				cursor: 'pointer'
			},
			buttonTextStyle = {
				color: 'white',
				fontSize: '18px',
				lineHeight: '18px',
				padding: '0 8px'
			},
			rightButtonStyle = {
				display: 'inline-block',
				textAlign: 'center',
				padding: '0px 16px 8px 0px',
				cursor: 'pointer',
				float: 'right'
			}

		return (
			<div style={{marginBottom: 0, overflowY: 'hidden'}}>
				<div style={{position: 'relative', width:'100%', height:'50px', backgroundColor:'black'}}>
					<div style={{display: 'inline-block', verticalAlign: 'top', width: '100%', height: '100%', paddingTop: '5px'}}>
						<div
							id='sellButton'
							style={buttonStyle}
							onTouchTap={this.goTo('sell')}
							onMouseOver={this.hoverSellOver}
							onMouseOut={this.hoverSellOut}>
							<h2 id='sellButtonText' style={buttonTextStyle}>SELL</h2>
						</div>
						<div
							id='buyButton'
							style={buttonStyle}
							onTouchTap={this.goTo('buy')}
							onMouseOver={this.hoverBuyOver}
							onMouseOut={this.hoverBuyOut}>
							<h2 id='buyButtonText' style={buttonTextStyle}>BUY</h2>
						</div>
						<div
							id='stockButton'
							style={buttonStyle}
							onTouchTap={this.goTo('stock')}
							onMouseOver={this.hoverStockOver}
							onMouseOut={this.hoverStockOut}>
							<h2 id='stockButtonText' style={buttonTextStyle}>STOCK</h2>
						</div>
						<div
							id='billButton'
							style={buttonStyle}
							onTouchTap={this.goTo('bill')}
							onMouseOver={this.hoverBillOver}
							onMouseOut={this.hoverBillOut}>
							<h2 id='billButtonText' style={buttonTextStyle}>BILL</h2>
						</div>
						{/*
						<div
							id='databaseButton'
							style={buttonStyle}
							onTouchTap={this.goTo('database')}
							onMouseOver={this.hoverDatabaseOver}
							onMouseOut={this.hoverDatabaseOut}>
							<h2 id='databaseButtonText' style={buttonTextStyle}>DATABASE</h2>
						</div>
						*/}
						<div
							id='login'
							style={rightButtonStyle}
							onTouchTap={this.goTo('login')}
							onMouseOver={this.hoverLoginOver}
							onMouseOut={this.hoverLoginOut}>
							<h2 id='loginButtonText' style={buttonTextStyle}>LOGOUT</h2>
						</div>
					</div>
				</div>
			</div>
		)
	}
}