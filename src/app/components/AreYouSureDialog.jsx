import React, { Component } from 'react'

import Dialog     from 'material-ui/Dialog'
import FlatButton from 'material-ui/FlatButton'

export default class AreYouSureDialog extends Component {

	static defaultProps = {
		open:  false,
		title: null,
		desc:  'Are You Sure?',
		onYes: () => {},
		onNo:  () => {},
		dialogModal: false,
		onRequestClose: () => {}
	}

	handleYes = () => {
		this.props.onYes()
		this.props.onRequestClose()		
	}

	handleNo = () => {
		this.props.onNo()
		this.props.onRequestClose()
	}

	render = () => {
		let dialogActions = [
				<FlatButton
					label="No"
					onTouchTap={this.handleNo} />,
				<FlatButton
					label="Yes"
					secondary={true}
					onTouchTap={this.handleYes} />
			]

		return (
			<Dialog
				open={this.props.open}
				title={this.props.title}
				actions={dialogActions}
				modal={this.props.dialogModal}
				contentStyle={{ width: '25%', textAlign: 'center' }}
				actionsContainerStyle={{ textAlign: 'center' }}
				onRequestClose={this.props.onRequestClose}>
				{this.props.desc}
			</Dialog>
		)
	}
}
