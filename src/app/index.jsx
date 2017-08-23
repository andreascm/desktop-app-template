import injectTapEventPlugin from 'react-tap-event-plugin'
injectTapEventPlugin()

import React, { Component } from 'react'
import ReactDOM 			from 'react-dom'
import MuiThemeProvider 	from 'material-ui/styles/MuiThemeProvider'

import ChangeUsernameDialog from './ChangeUsernameDialog.jsx'
import ChangePasswordDialog from './ChangePasswordDialog.jsx'

import RaisedButton from 'material-ui/RaisedButton'
import Paper        from 'material-ui/Paper'
import TextField    from 'material-ui/TextField'

export default class Login extends Component {
	state = {
		returnTo: '',
		okMessage: 'Login',
		errorMessage: null,

		changeUsernameDialogOpen: false,
		changePasswordDialogOpen: false
	}

	error = (message) => { this.setState({ errorMessage: message }) }
	ok = (message) => { this.setState({ okMessage: message }) }

	componentDidMount = () => {
		let login = getQueryVariable('login'),
			error = getQueryVariable('error'),
			success = getQueryVariable('success'),
			returnTo = getQueryVariable('returnTo')

		if (login === 'failed') {
			this.error('Wrong username or password')
			this.ok('Please try again')
		}

		if (error) {
			this.error(decodeURIComponent(error))
		}

		if (success) {
			this.ok(decodeURIComponent(success))
		}

		if (returnTo) {
			this.setState({ returnTo: returnTo })
		}
	}

	handleChangeUsername = () => {
		this.setState({ changeUsernameDialogOpen: true })
	}

	handleCloseChangeUsernameDialog = () => {
		this.setState({ changeUsernameDialogOpen: false })
	}

	handleChangePassword = () => {
		this.setState({ changePasswordDialogOpen: true })
	}

	handleCloseChangePasswordDialog = () => {
		this.setState({ changePasswordDialogOpen: false })
	}

	render = () => {
		var loginFormStyle = {
				width: '320px',
				minWidht: '320px',
				margin: '0px auto',
				textAlign: 'center',
				marginTop: '20px',
				padding: '10px 0 30px 0',
				backgroundColor: 'white'
			},
			errorStyle = {
				color: red,
				fontSize: '16px',
				padding: '5px 0',
				fontWeight: 'bold',
				lineHeight: '24px',
			},
			okStyle = {
				color: 'black',
				fontSize: '20px',
				padding: '5px 0',
				fontWeight: 'bold',
				lineHeight: '24px'
			}

		return (
			<div style={{width: '100%', float: 'left', marginBottom: '175px', marginTop: '175px'}}>
				<form action='/passwordCheck' method='POST' id='loginForm'>
					<div style={{clear: 'both'}}>
						<Paper style={loginFormStyle} zDepth={1}>
							{ this.state.errorMessage ? 
								<div style={errorStyle}>{this.state.errorMessage}</div>
								: null
							}
							{ this.state.okMessage ?
								<div style={okStyle}>{this.state.okMessage}</div>
								: null
							}
							<TextField
								floatingLabelStyle={{color: grey, fontWeight: 'normal'}}
								floatingLabelText="Username"
								inputStyle={{color: 'black'}}
								id="username"
								hintText=""
								name="username" />
							<TextField
								floatingLabelStyle={{color: grey, fontWeight: 'normal'}}
								floatingLabelText="Password"
								inputStyle={{color: 'black'}}
								id="password"
								type="password"
								hintText=""
								name="password" />
							<br /><br />
							<RaisedButton
								label='Change Username'
								labelColor='white'
								backgroundColor='black'
								onTouchTap={this.handleChangeUsername} />
							<br /><br />
							<RaisedButton
								label='Change Password'
								labelColor='white'
								backgroundColor='black'
								onTouchTap={this.handleChangePassword} />
							<br /><br />
							<RaisedButton
								label="Submit"
								labelColor='white'
								backgroundColor='black'
								form='loginForm'
								type='submit' />
						</Paper>
					</div>
					<input type='hidden' name='returnTo' value={this.state.returnTo} />
				</form>
				<ChangeUsernameDialog
					open={this.state.changeUsernameDialogOpen}
					handleClose={this.handleCloseChangeUsernameDialog} />
				<ChangePasswordDialog
					open={this.state.changePasswordDialogOpen}
					handleClose={this.handleCloseChangePasswordDialog} />
			</div>
		)
	}
}

ReactDOM.render(<MuiThemeProvider><Login /></MuiThemeProvider>, document.getElementById('container'))