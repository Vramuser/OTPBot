const { Client, GatewayIntentBits, SlashCommandBuilder, REST, Routes } = require('discord.js');
const { TOTP, Secret } = require('otpauth');

const BOT_TOKEN = 'BOT_TOKEN_HERE';
const CLIENT_ID = 'CLIENT_ID_HERE';

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.DirectMessages
    ]
});

const userSecrets = new Map();

function getCurrentSeconds() {
    return Math.round(new Date().getTime() / 1000.0);
}

function stripSpaces(str) {
    return str.replace(/\s/g, '');
}

function truncateTo(str, digits) {
    if (str.length <= digits) {
        return str;
    }
    return str.slice(-digits);
}

const commands = [
    new SlashCommandBuilder()
        .setName('setup-totp')
        .setDescription('Set up TOTP authentication')
        .addStringOption(option =>
            option.setName('secret')
                .setDescription('Your TOTP secret key (optional - will generate if not provided)')
                .setRequired(false)
        ),
    
    new SlashCommandBuilder()
        .setName('generate-code')
        .setDescription('Generate a TOTP code'),
    
    new SlashCommandBuilder()
        .setName('verify-code')
        .setDescription('Verify a TOTP code')
        .addStringOption(option =>
            option.setName('code')
                .setDescription('The 6-digit code to verify')
                .setRequired(true)
        ),
    
    new SlashCommandBuilder()
        .setName('login')
        .setDescription('Login using your secret key')
        .addStringOption(option =>
            option.setName('secret')
                .setDescription('Your TOTP secret key')
                .setRequired(true)
        ),

    new SlashCommandBuilder()
        .setName('custom-login')
        .setDescription('Login with custom TOTP settings')
        .addStringOption(option =>
            option.setName('secret')
                .setDescription('Your TOTP secret key')
                .setRequired(true)
        )
        .addStringOption(option =>
            option.setName('algorithm')
                .setDescription('Hash algorithm (default: SHA1)')
                .setRequired(false)
                .addChoices(
                    { name: 'SHA1', value: 'SHA1' },
                    { name: 'SHA256', value: 'SHA256' },
                    { name: 'SHA512', value: 'SHA512' }
                )
        )
        .addIntegerOption(option =>
            option.setName('digits')
                .setDescription('Number of digits (default: 6)')
                .setRequired(false)
                .addChoices(
                    { name: '6 digits', value: 6 },
                    { name: '8 digits', value: 8 }
                )
        )
        .addIntegerOption(option =>
            option.setName('period')
                .setDescription('Time period in seconds (default: 30)')
                .setRequired(false)
        ),

    new SlashCommandBuilder()
        .setName('test-website')
        .setDescription('Test if your secret matches the website code')
        .addStringOption(option =>
            option.setName('secret')
                .setDescription('Your TOTP secret key')
                .setRequired(true)
        )
        .addStringOption(option =>
            option.setName('website_code')
                .setDescription('The current code showing on the website')
                .setRequired(true)
        )
];

async function registerCommands() {
    try {
        const rest = new REST({ version: '10' }).setToken(BOT_TOKEN);
        console.log('Started refreshing application commands.');

        await rest.put(
            Routes.applicationCommands(CLIENT_ID),
            { body: commands }
        );

        console.log('Successfully registered application commands.');
    } catch (error) {
        console.error('Error registering commands:', error);
    }
}

client.once('ready', () => {
    console.log(`Logged in as ${client.user.tag}!`);
    registerCommands();
});

client.on('interactionCreate', async interaction => {
    if (!interaction.isChatInputCommand()) return;

    const { commandName, user } = interaction;
    const userId = user.id;

    try {
        switch (commandName) {
            case 'setup-totp':
                await handleSetupTOTP(interaction, userId);
                break;
            
            case 'generate-code':
                await handleGenerateCode(interaction, userId);
                break;
            
            case 'verify-code':
                await handleVerifyCode(interaction, userId);
                break;
            
            case 'login':
                await handleLogin(interaction, userId);
                break;
            
            case 'custom-login':
                await handleCustomLogin(interaction, userId);
                break;
            
            case 'test-website':
                await handleTestWebsite(interaction, userId);
                break;
            
            default:
                await interaction.reply({
                    content: 'Unknown command.',
                    ephemeral: true
                });
                break;
        }
    } catch (error) {
        console.error('Error handling command:', error);
        
        if (!interaction.replied && !interaction.deferred) {
            await interaction.reply({
                content: 'An error occurred while processing your command.',
                ephemeral: true
            });
        }
    }
});

function createTOTP(secretKey, algorithm = 'SHA1', digits = 6, period = 30) {
    try {
        const cleanSecret = stripSpaces(secretKey);
        return new TOTP({
            algorithm: algorithm,
            digits: digits,
            period: period,
            secret: Secret.fromBase32(cleanSecret)
        });
    } catch (error) {
        console.error('Error creating TOTP:', error);
        throw new Error(`Failed to create TOTP: ${error.message}`);
    }
}

function generateToken(totp, digits) {
    const token = totp.generate();
    return truncateTo(token, digits);
}

async function handleSetupTOTP(interaction, userId) {
    try {
        const providedSecret = interaction.options.getString('secret');
        
        let secret;
        if (providedSecret) {
            try {
                const cleanSecret = stripSpaces(providedSecret);
                secret = Secret.fromBase32(cleanSecret);
            } catch (error) {
                return await interaction.reply({
                    content: 'Invalid secret format. Please provide a valid base32 encoded secret.',
                    ephemeral: true
                });
            }
        } else {
            secret = new Secret();
        }

        const totp = new TOTP({
            algorithm: 'SHA1',
            digits: 6,
            period: 30,
            secret: secret
        });

        userSecrets.set(userId, totp);

        await interaction.reply({
            content: `TOTP setup complete!\n\nYour Secret Key: \`${secret.base32}\`\n\nKeep this secret safe! You can use it to set up TOTP in authenticator apps.\n\nTip: You can use \`/login\` with this secret key to restore access later.`,
            ephemeral: true
        });
    } catch (error) {
        console.error('Error in handleSetupTOTP:', error);
        if (!interaction.replied) {
            await interaction.reply({
                content: 'An error occurred during TOTP setup. Please try again.',
                ephemeral: true
            });
        }
    }
}

async function handleGenerateCode(interaction, userId) {
    const totp = userSecrets.get(userId);
    
    if (!totp) {
        return await interaction.reply({
            content: 'You haven\'t set up TOTP yet. Use `/setup-totp` or `/login` first.',
            ephemeral: true
        });
    }

    const token = generateToken(totp, totp.digits);
    const updatingIn = totp.period - (getCurrentSeconds() % totp.period);
    
    await interaction.reply({
        content: `Current TOTP Code: \`${token}\`\nValid for: ${updatingIn} seconds\nSettings: ${totp.algorithm}, ${totp.digits} digits, ${totp.period}s period`,
        ephemeral: true
    });
}

async function handleVerifyCode(interaction, userId) {
    const totp = userSecrets.get(userId);
    const codeToVerify = interaction.options.getString('code');
    
    if (!totp) {
        return await interaction.reply({
            content: 'You haven\'t set up TOTP yet. Use `/setup-totp` or `/login` first.',
            ephemeral: true
        });
    }

    const delta = totp.validate({
        token: codeToVerify,
        window: 1
    });

    if (delta !== null) {
        await interaction.reply({
            content: `Code verified successfully!\nCode: \`${codeToVerify}\`\nDelta: ${delta} periods`,
            ephemeral: true
        });
    } else {
        await interaction.reply({
            content: `Invalid or expired code.\nCode: \`${codeToVerify}\`\nPlease try with a current code.`,
            ephemeral: true
        });
    }
}

async function handleLogin(interaction, userId) {
    const providedSecret = interaction.options.getString('secret');
    
    if (!providedSecret) {
        return await interaction.reply({
            content: 'Please provide your secret key.',
            ephemeral: true
        });
    }

    try {
        const totp = createTOTP(providedSecret, 'SHA1', 6, 30);
        const currentToken = generateToken(totp, 6);
        
        userSecrets.set(userId, totp);
        
        await interaction.reply({
            content: `Login successful!\n\nCurrent Code: \`${currentToken}\`\nSettings: SHA1, 6 digits, 30s period\n\nYou can now use \`/generate-code\` and \`/verify-code\` commands.`,
            ephemeral: true
        });
        
    } catch (error) {
        console.error('Login error:', error);
        await interaction.reply({
            content: `Login failed!\n\nError: ${error.message}\n\nMake sure your secret key is valid base32 format.`,
            ephemeral: true
        });
    }
}

async function handleCustomLogin(interaction, userId) {
    const providedSecret = interaction.options.getString('secret');
    const algorithm = interaction.options.getString('algorithm') || 'SHA1';
    const digits = interaction.options.getInteger('digits') || 6;
    const period = interaction.options.getInteger('period') || 30;
    
    if (!providedSecret) {
        return await interaction.reply({
            content: 'Please provide your secret key.',
            ephemeral: true
        });
    }

    try {
        const totp = createTOTP(providedSecret, algorithm, digits, period);
        const currentToken = generateToken(totp, digits);
        
        userSecrets.set(userId, totp);
        
        await interaction.reply({
            content: `Custom login successful!\n\nCurrent Code: \`${currentToken}\`\nSettings: ${algorithm}, ${digits} digits, ${period}s period\n\nYou can now use \`/generate-code\` and \`/verify-code\` commands.`,
            ephemeral: true
        });
        
    } catch (error) {
        console.error('Custom login error:', error);
        await interaction.reply({
            content: `Custom login failed!\n\nError: ${error.message}`,
            ephemeral: true
        });
    }
}

async function handleTestWebsite(interaction, userId) {
    const providedSecret = interaction.options.getString('secret');
    const websiteCode = interaction.options.getString('website_code');
    
    if (!providedSecret || !websiteCode) {
        return await interaction.reply({
            content: 'Please provide both secret key and website code.',
            ephemeral: true
        });
    }

    try {
        const totp = createTOTP(providedSecret, 'SHA1', 6, 30);

        const currentTime = Date.now();
        const results = [];
        
        for (let offset = -2; offset <= 2; offset++) {
            const testTime = currentTime + (offset * 30 * 1000);
            const testToken = totp.generate({ timestamp: testTime });
            const truncatedToken = truncateTo(testToken, 6);
            const timeWindow = Math.floor(testTime / 1000 / 30);
            
            results.push({
                offset,
                code: truncatedToken,
                timeWindow,
                matches: truncatedToken === websiteCode
            });
        }
        
        const matchingResult = results.find(r => r.matches);
        const currentToken = generateToken(totp, 6);
        const updatingIn = 30 - (getCurrentSeconds() % 30);
        
        let response = `Website Test Results\n\n`;
        response += `Secret: \`${stripSpaces(providedSecret)}\`\n`;
        response += `Website Code: \`${websiteCode}\`\n`;
        response += `Bot Code: \`${currentToken}\`\n`;
        response += `Time until next: ${updatingIn}s\n\n`;
        
        if (matchingResult) {
            response += `Match found! Offset: ${matchingResult.offset} periods\n`;
            response += `This secret works with the website!\n\n`;
            response += `You can now use: \`/login secret:${stripSpaces(providedSecret)}\``;
        } else {
            response += `No exact match found.\n\nTested time windows:\n`;
            results.forEach(r => {
                response += `Offset ${r.offset}: \`${r.code}\`${r.matches ? ' ✓' : ''}\n`;
            });
        }
        
        await interaction.reply({
            content: response,
            ephemeral: true
        });
        
    } catch (error) {
        console.error('Test website error:', error);
        await interaction.reply({
            content: `Test failed!\n\nError: ${error.message}`,
            ephemeral: true
        });
    }
}

process.on('unhandledRejection', error => {
    console.error('Unhandled promise rejection:', error);
});

client.login(BOT_TOKEN);