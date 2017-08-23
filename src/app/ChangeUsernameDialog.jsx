import React, { Component } from 'react'

import CloseButton from 'CloseButton.jsx'

import AutoComplete from 'material-ui/AutoComplete'
import Dialog from 'material-ui/Dialog'
import FlatButton from 'material-ui/FlatButton'
import RaisedButton from 'material-ui/RaisedButton'
import TextField from 'material-ui/TextField'

export default class ChangeUsernameDialog extends Component {
	static defaultProps = {
		open: false,
		handleClose: () => {},
	}

	state = {
		returnTo: ''
	}

	render = () => {
		var actions = [
				<FlatButton label='Close' onTouchTap={this.props.handleClose}/>,
				<FlatButton label='Submit' secondary={true} form='changeUsernameForm' type='submit'/>
			],
			headerStyle = {
				height: '30px',
				fontSize: '14px',
				verticalAlign: 'middle',
				lineHeight: '30px'
			}

		return (
			<Dialog
				open={this.props.open}
				title='Change Username'
				actions={actions}
				onRequestClose={this.props.handleClose}
				contentStyle={{width: '80%', maxWidth: 'none'}}>
				<CloseButton onTouchTap={this.props.handleClose} />
				<form action='/changeUsername' method='POST' id='changeUsernameForm'>
					<div style={{clear: 'both'}}>
						{ this.state.errorMessage ? 
							<div>{this.state.errorMessage}</div>
							: null
						}
						{ this.state.okMessage ?
							<div>{this.state.okMessage}</div>
							: null
						}
						<TextField
							floatingLabelStyle={{color: grey, fontWeight: 'normal'}}
							floatingLabelText="Old Username"
							inputStyle={{color: 'black'}}
							id="username"
							hintText=""
							name="username" />
						<TextField
							floatingLabelStyle={{color: grey, fontWeight: 'normal'}}
							floatingLabelText="New Username"
							inputStyle={{color: 'black'}}
							id="newUsername"
							hintText=""
							name="newUsername" />
						<TextField
							floatingLabelStyle={{color: grey, fontWeight: 'normal'}}
							floatingLabelText="Password"
							inputStyle={{color: 'black'}}
							id="password"
							type="password"
							hintText=""
							name="password" />
					</div>
					<input type='hidden' name='returnTo' value={this.state.returnTo} />
				</form>
			</Dialog>
		)
	}
}