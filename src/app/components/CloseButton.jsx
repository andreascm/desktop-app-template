import React, { Component } from 'react'

import FlatButton from 'material-ui/FlatButton'

export default class CloseButton extends Component {

	static defaultProps = {
		style:      {},
		labelStyle: {},
		onTouchTap: () => {}
	}

	render = () => {
		let xStyle = Object.assign({}, {
				minWidth: 0,
				width:    '32px',
				height:   '32px',
				lineHeight: '32px',
				position: 'absolute',
				top:      0,
				right:    0,
				padding:  0,
				margin:   '16px',
				color:    '#222',
				borderRadius: '15px'
			}, this.props.style),
			labelStyle = Object.assign({}, {
				padding: '2px 2px 2px 2px',
				fontSize: '24px',
			}, this.props.labelStyle)

		return (
			<FlatButton
				style={xStyle}
				backgroundColor="transparent"
				hoverColor='#EEE'
				label={'X'}
				labelStyle={labelStyle}
				onTouchTap={this.props.onTouchTap}
			/>
		)
	}
}