<#
.SYNOPSIS
	"Windows 10 Setup Script" is a set of tweaks for OS fine-tuning and automating the routine tasks

	Version: v4.5.6
	Date: 03.08.2020
	Copyright (c) 2020 farag & oZ-Zo

	Thanks to all http://forum.ru-board.com members involved

.DESCRIPTION
	Supported Windows 10 version: 2004 (20H1), 19041 build, x64
	Most of functions can be run also on LTSB/LTSC

	Tested on Home/Pro/Enterprise editions

	Due to the fact that the script includes about 150 functions,
	you must read the entire script and comment out those sections that you do not want to be executed,
	otherwise likely you will enable features that you do not want to be enabled

	Running the script is best done on a fresh install because running it on tweaked system may result in errors occurring

	Some third-party antiviruses flag this script or its' part as malicious one. This is a false positive due to $EncodedScript variable
	You can read more on section "Create a Windows cleaning up task in the Task Scheduler"
	You might need to disable tamper protection from your antivirus settings,re-enable it after running the script, and reboot

	Check whether the .ps1 file is encoded in UTF-8 with BOM
	The script can not be executed via PowerShell ISE
	PowerShell must be run with elevated privileges

	Set execution policy to be able to run scripts only in the current PowerShell session:
		Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

.EXAMPLE
	PS C:\> & '.\Win 10 2004.ps1'

.NOTES
	Ask a question on
	http://forum.ru-board.com/topic.cgi?forum=62&topic=30617#15
	https://habr.com/en/post/465365/
	https://4pda.ru/forum/index.php?showtopic=523489&st=42860#entry95909388
	https://forums.mydigitallife.net/threads/powershell-script-setup-windows-10.81675/
	https://www.reddit.com/r/PowerShell/comments/go2n5v/powershell_script_setup_windows_10/

.LINK
	https://github.com/farag2/Windows-10-Setup-Script
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

#region Check
Clear-Host

# Get information about the current culture settings
# Получить сведения о параметрах текущей культуры
if ($PSUICulture -eq "ru-RU")
{
	$RU = $true
}
else
{
	$RU = $false
}

# Detect the OS bitness
# Определить разрядность ОС
switch ([Environment]::Is64BitOperatingSystem)
{
	$false
	{
		if ($RU)
		{
			Write-Warning -Message "Скрипт поддерживает только Windows 10 x64"
		}
		else
		{
			Write-Warning -Message "The script supports Windows 10 x64 only"
		}
		break
	}
	Default {}
}

# Detect the PowerShell bitness
# Определить разрядность PowerShell
switch ([IntPtr]::Size -eq 8)
{
	$false
	{
		if ($RU)
		{
			Write-Warning -Message "Скрипт поддерживает только PowerShell x64"
		}
		else
		{
			Write-Warning -Message "The script supports PowerShell x64 only"
		}
		break
	}
	Default {}
}

# Detect whether the script is running via PowerShell ISE
# Определить, запущен ли скрипт в PowerShell ISE
if ($psISE)
{
	if ($RU)
	{
		Write-Warning -Message "Скрипт не может быть запущен в PowerShell ISE"
	}
	else
	{
		Write-Warning -Message "The script can not be run via PowerShell ISE"
	}
	break
}
#endregion Check

#region Begin
Set-StrictMode -Version Latest

# Сlear $Error variable
# Очистка переменной $Error
$Error.Clear()

# Create a restore point
# Создать точку восстановления
if ($RU)
{
	$Title = "Точка восстановления"
	$Message = "Чтобы создайте точку восстановления, введите необходимую букву"
	$Options = "&Создать", "&Не создавать", "&Пропустить"
}
else
{
	$Title = "Restore point"
	$Message = "To create a restore point enter the required letter"
	$Options = "&Create", "&Do not create", "&Skip"
}
$DefaultChoice = 2
$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

switch ($Result)
{
	"0"
	{
		if (-not (Get-ComputerRestorePoint))
		{
			Enable-ComputerRestore -Drive $env:SystemDrive
		}
		# Set system restore point creation frequency to 5 minutes
		# Установить частоту создания точек восстановления на 5 минут
		New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name SystemRestorePointCreationFrequency -PropertyType DWord -Value 5 -Force
		# Descriptive name format for the restore point: <Month>.<date>.<year> <time>
		# Формат описания точки восстановления: <дата>.<месяц>.<год> <время>
		$CheckpointDescription = Get-Date -Format "dd.MM.yyyy HH:mm"
		Checkpoint-Computer -Description $CheckpointDescription -RestorePointType MODIFY_SETTINGS
		New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name SystemRestorePointCreationFrequency -PropertyType DWord -Value 1440 -Force
	}
	"1"
	{
		if ($RU)
		{
			$Title = "Точки восстановления"
			$Message = "Чтобы удалить все точки восстановления, введите необходимую букву"
			$Options = "&Удалить", "&Пропустить"
		}
		else
		{
			$Title = "Restore point"
			$Message = "To remove all restore points enter the required letter"
			$Options = "&Delete", "&Skip"
		}
		$DefaultChoice = 1
		$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

		switch ($Result)
		{
			"0"
			{
				# Delete all restore points
				# Удалить все точки восстановения
				Get-CimInstance -ClassName Win32_ShadowCopy | Remove-CimInstance
			}
			"1"
			{
				if ($RU)
				{
					Write-Verbose -Message "Пропущено" -Verbose
				}
				else
				{
					Write-Verbose -Message "Skipped" -Verbose
				}
			}
		}
	}
	"2"
	{
		if ($RU)
		{
			Write-Verbose -Message "Пропущено" -Verbose
		}
		else
		{
			Write-Verbose -Message "Skipped" -Verbose
		}
	}
}
#endregion Begin

#region Privacy & Telemetry
# Turn off "Connected User Experiences and Telemetry" service
# Отключить службу "Функциональные возможности для подключенных пользователей и телеметрия"
Get-Service -Name DiagTrack | Stop-Service -Force
Get-Service -Name DiagTrack | Set-Service -StartupType Disabled

# Turn off per-user services
# Отключить cлужбы для отдельных пользователей
$services = @(
	# Contact Data
	# Служба контактных данных
	"PimIndexMaintenanceSvc_*"
	# User Data Storage
	# Служба хранения данных пользователя
	"UnistoreSvc_*"
	# User Data Access
	# Служба доступа к данным пользователя
	"UserDataSvc_*"
)
Get-Service -Name $services | Stop-Service -Force
New-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\PimIndexMaintenanceSvc -Name Start -PropertyType DWord -Value 4 -Force
New-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\PimIndexMaintenanceSvc -Name UserServiceFlags -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\UnistoreSvc -Name Start -PropertyType DWord -Value 4 -Force
New-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\UnistoreSvc -Name UserServiceFlags -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\UserDataSvc -Name Start -PropertyType DWord -Value 4 -Force
New-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\UserDataSvc -Name UserServiceFlags -PropertyType DWord -Value 0 -Force

# Set the minimal operating system diagnostic data level
# Установить минимальный уровень отправляемых диагностических сведений
if ((Get-WindowsEdition -Online).Edition -eq "Enterprise" -or (Get-WindowsEdition -Online).Edition -eq "Education")
{
	# "Security"
	# "Безопасность"
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Name AllowTelemetry -PropertyType DWord -Value 0 -Force
}
else
{
	# "Basic"
	# "Базовый"
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Name AllowTelemetry -PropertyType DWord -Value 1 -Force
}

# Turn off Windows Error Reporting
# Отключить отчеты об ошибках Windows
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\Windows Error Reporting" -Name Disabled -PropertyType DWord -Value 1 -Force

# Change Windows Feedback frequency to "Never"
# Изменить частоту формирования отзывов на "Никогда"
if (-not (Test-Path -Path HKCU:\Software\Microsoft\Siuf\Rules))
{
	New-Item -Path HKCU:\Software\Microsoft\Siuf\Rules -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Siuf\Rules -Name NumberOfSIUFInPeriod -PropertyType DWord -Value 0 -Force

# Turn off diagnostics tracking scheduled tasks
# Отключить задачи диагностического отслеживания
$tasks = @(
	# Collects program telemetry information if opted-in to the Microsoft Customer Experience Improvement Program.
	# Собирает телеметрические данные программы при участии в Программе улучшения качества программного обеспечения Майкрософт
	"Microsoft Compatibility Appraiser"
	# Collects program telemetry information if opted-in to the Microsoft Customer Experience Improvement Program
	# Сбор телеметрических данных программы при участии в программе улучшения качества ПО
	"ProgramDataUpdater"
	# This task collects and uploads autochk SQM data if opted-in to the Microsoft Customer Experience Improvement Program
	# Эта задача собирает и загружает данные SQM при участии в программе улучшения качества программного обеспечения
	"Proxy"
	# If the user has consented to participate in the Windows Customer Experience Improvement Program, this job collects and sends usage data to Microsoft
	# Если пользователь изъявил желание участвовать в программе по улучшению качества программного обеспечения Windows, эта задача будет собирать и отправлять сведения о работе программного обеспечения в Майкрософт
	"Consolidator"
	# The USB CEIP (Customer Experience Improvement Program) task collects Universal Serial Bus related statistics and information about your machine
	# При выполнении задачи программы улучшения качества ПО шины USB (USB CEIP) осуществляется сбор статистических данных об использовании универсальной последовательной шины USB и сведений о компьютере
	"UsbCeip"
	# The Windows Disk Diagnostic reports general disk and system information to Microsoft for users participating in the Customer Experience Program
	# Для пользователей, участвующих в программе контроля качества программного обеспечения, служба диагностики дисков Windows предоставляет общие сведения о дисках и системе в корпорацию Майкрософт
	"Microsoft-Windows-DiskDiagnosticDataCollector"
	# Protects user files from accidental loss by copying them to a backup location when the system is unattended
	# Защищает файлы пользователя от случайной потери за счет их копирования в резервное расположение, когда система находится в автоматическом режиме
	"File History (maintenance mode)"
	# Measures a system's performance and capabilities
	# Измеряет быстродействие и возможности системы
	"WinSAT"
	# This task shows various Map related toasts
	# Эта задача показывает различные тосты (всплывающие уведомления) приложения "Карты"
	"MapsToastTask"
	# This task checks for updates to maps which you have downloaded for offline use
	# Эта задача проверяет наличие обновлений для карт, загруженных для автономного использования
	"MapsUpdateTask"
	# Initializes Family Safety monitoring and enforcement
	# Инициализация контроля и применения правил семейной безопасности
	"FamilySafetyMonitor"
	# Synchronizes the latest settings with the Microsoft family features service
	# Синхронизирует последние параметры со службой функций семьи учетных записей Майкрософт
	"FamilySafetyRefreshTask"
	# Windows Error Reporting task to process queued reports
	# Задача отчетов об ошибках обрабатывает очередь отчетов
	"QueueReporting"
	# XblGameSave Standby Task
	"XblGameSaveTask"
)
# If device is not a laptop
# Если устройство не является ноутбуком
if ((Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType -ne 2)
{
	# HelloFace
	$tasks += "FODCleanupTask"
}
Get-ScheduledTask -TaskName $tasks | Disable-ScheduledTask

# Do not let websites provide locally relevant content by accessing language list
# Не позволять веб-сайтам предоставлять местную информацию за счет доступа к списку языков
New-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name HttpAcceptLanguageOptOut -PropertyType DWord -Value 1 -Force

# Do not allow apps to use advertising ID
# Не разрешать приложениям использовать идентификатор рекламы
if (-not (Test-Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -PropertyType DWord -Value 0 -Force

# Do not let apps on other devices open and message apps on this device, and vice versa
# Не разрешать приложениям на других устройствах запускать приложения и отправлять сообщения на этом устройстве и наоборот
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP -Name RomeSdkChannelUserAuthzPolicy -PropertyType DWord -Value 0 -Force

# Do not show the Windows welcome experiences after updates and occasionally when I sign in to highlight what's new and suggested
# Не показывать экран приветствия Windows после обновлений и иногда при входе, чтобы сообщить о новых функциях и предложениях
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-310093Enabled -PropertyType DWord -Value 0 -Force

# Get tip, trick, and suggestions as you use Windows
# Получать советы, подсказки и рекомендации при использованию Windows
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338389Enabled -PropertyType DWord -Value 1 -Force

# Do not show suggested content in the Settings app
# Не показывать рекомендуемое содержимое в приложении "Параметры"
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338393Enabled -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-353694Enabled -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-353696Enabled -PropertyType DWord -Value 0 -Force

# Turn off automatic installing suggested apps
# Отключить автоматическую установку рекомендованных приложений
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SilentInstalledAppsEnabled -PropertyType DWord -Value 0 -Force

# Do not suggest ways I can finish setting up my device to get the most out of Windows
# Не предлагать способы завершения настройки устройства для максимально эффективного использования Windows
if (-not (Test-Path HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement -Name ScoobeSystemSettingEnabled -PropertyType DWord -Value 0 -Force

# Do not offer tailored experiences based on the diagnostic data setting
# Не предлагать персонализированные возможности, основанные на выбранном параметре диагностических данных
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy -Name TailoredExperiencesWithDiagnosticDataEnabled -PropertyType DWord -Value 0 -Force
#endregion Privacy & Telemetry

# Turn on Windows 10 20H2 new Start style
# Включить новый стиль Пуска как в Windows 10 20H2
if (Get-HotFix -Id KB4568831 -ErrorAction Ignore)
{
	if (-not (Test-Path -Path HKLM:\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\0\2093230218s))
	{
		New-Item -Path HKLM:\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\0\2093230218 -Force
	}
	New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\0\2093230218 -Name EnabledState -PropertyType DWORD -Value 2 -Force
	New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\0\2093230218 -Name EnabledStateOptions -PropertyType DWORD -Value 0 -Force
}

#region System


# Group svchost.exe processes
# Группировать процессы svchost.exe
$RAMCapacity = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1KB
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control -Name SvcHostSplitThresholdInKB -PropertyType DWord -Value $RAMCapacity -Force

# Turn off Windows features
# Отключить компоненты Windows
$WindowsOptionalFeatures = @(
	# Legacy Components
	# Компоненты прежних версий
	"LegacyComponents"
	# Media Features
	# Компоненты работы с мультимедиа
	"MediaPlayback"
	# PowerShell 2.0
	"MicrosoftWindowsPowerShellV2"
	"MicrosoftWindowsPowershellV2Root"
	# Microsoft XPS Document Writer
	# Средство записи XPS-документов (Microsoft)
	"Printing-XPSServices-Features"
	# Microsoft Print to PDF
	# Печать в PDF (Майкрософт)
	"Printing-PrintToPDFServices-Features"
	# Work Folders Client
	# Клиент рабочих папок
	"WorkFolders-Client"
)
Disable-WindowsOptionalFeature -Online -FeatureName $WindowsOptionalFeatures -NoRestart

# Remove Windows capabilities
# Удалить дополнительные компоненты Windows
Add-Type -AssemblyName PresentationCore, PresentationFramework

#region Variables
# Windows capabilities array list to remove
# Массив имен дополнительных компонентов Windows для удаления
$Capabilities = New-Object -TypeName System.Collections.ArrayList($null)

# Windows capabilities that will be checked to remove by default
# Дополнительные компоненты Windows, которые будут отмечены на удаление по умолчанию
$CheckedCapabilities = @(
	# Steps Recorder
	# Средство записи действий
	"App.StepsRecorder*"
	# Microsoft Quick Assist
	# Быстрая поддержка (Майкрософт)
	"App.Support.QuickAssist*"
	# Windows Media Player
	# Проигрыватель Windows Media
	"Media.WindowsMediaPlayer*"
	# Microsoft Paint
	"Microsoft.Windows.MSPaint*"
	# WordPad
	"Microsoft.Windows.WordPad*"
	# Integrated faxing and scanning application for Windows
	# Факсы и сканирование Windows
	"Print.Fax.Scan*"
)
# If device is not a laptop
# Если устройство не является ноутбуком
if ((Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType -ne 2)
{
	# Windows Hello Face
	# Распознавание лиц Windows Hello
	$CheckedCapabilities += "Hello.Face*"
}
# Windows capabilities that will be shown in the form
# Дополнительные компоненты Windows, которые будут выводиться в форме
$ExcludedCapabilities = @(
	# The DirectX Database to configure and optimize apps when multiple Graphics Adapters are present
	# База данных DirectX для настройки и оптимизации приложений при наличии нескольких графических адаптеров
	"DirectX\.Configuration\.Database"
	# Language components
	# Языковые компоненты
	"Language\."
	# Notepad
	# Блокнот
	"Microsoft.Windows.Notepad*"
	# Mail, contacts, and calendar sync component
	# Компонент синхронизации почты, контактов и календаря
	"OneCoreUAP\.OneSync"
	# Management of printers, printer drivers, and printer servers
	# Управление принтерами, драйверами принтеров и принт-серверами
	"Print\.Management\.Console"
	# Features critical to Windows functionality
	# Компоненты, критичные для работоспособности Windows
	"Windows\.Client\.ShellComponents"
)
#endregion Variables

#region XAML Markup
[xml]$XAML = '
<Window
	xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
	xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
	Name="Window"
	MinHeight="450" MinWidth="400"
	SizeToContent="Width" WindowStartupLocation="CenterScreen"
	TextOptions.TextFormattingMode="Display" SnapsToDevicePixels="True"
	FontFamily="Segoe UI" FontSize="12" ShowInTaskbar="False">
	<Window.Resources>
		<Style TargetType="StackPanel">
			<Setter Property="Orientation" Value="Horizontal"/>
		</Style>
		<Style TargetType="CheckBox">
			<Setter Property="Margin" Value="10, 10, 5, 10"/>
			<Setter Property="IsChecked" Value="True"/>
		</Style>
		<Style TargetType="TextBlock">
			<Setter Property="Margin" Value="5, 10, 10, 10"/>
		</Style>
		<Style TargetType="Button">
			<Setter Property="Margin" Value="20"/>
			<Setter Property="Padding" Value="10"/>
		</Style>
	</Window.Resources>
	<Grid>
		<Grid.RowDefinitions>
			<RowDefinition Height="*"/>
			<RowDefinition Height="Auto"/>
		</Grid.RowDefinitions>
		<ScrollViewer Name="Scroll" Grid.Row="0"
			HorizontalScrollBarVisibility="Disabled"
			VerticalScrollBarVisibility="Auto">
			<StackPanel Name="PanelContainer" Orientation="Vertical"/>
		</ScrollViewer>
		<Button Name="Button" Grid.Row="1"/>
	</Grid>
</Window>
'
#endregion XAML Markup

$Reader = (New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $XAML)
$Form = [Windows.Markup.XamlReader]::Load($Reader)
$XAML.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object -Process {
	Set-Variable -Name ($_.Name) -Value $Form.FindName($_.Name) -Scope Global
}

#region Functions
function Get-CheckboxClicked
{
	[CmdletBinding()]
	param
	(
		[Parameter(
			Mandatory = $true,
			ValueFromPipeline = $true
		)]
		[ValidateNotNull()]
		$CheckBox
	)

	$Capability = $CheckBox.Parent.Children[1].Text
	if ($CheckBox.IsChecked)
	{
		[void]$Capabilities.Add($Capability)
	}
	else
	{
		[void]$Capabilities.Remove($Capability)
	}
	if ($Capabilities.Count -gt 0)
	{
		$Button.IsEnabled = $true
	}
	else
	{
		$Button.IsEnabled = $false
	}
}

function DeleteButton
{
	[void]$Window.Close()
	$OFS = "|"
	Get-WindowsCapability -Online | Where-Object -FilterScript {$_.Name -cmatch $Capabilities} | Remove-WindowsCapability -Online
	$OFS = " "
}

function Add-CapabilityControl
{
	[CmdletBinding()]
	param
	(
		[Parameter(
			Mandatory = $true,
			ValueFromPipeline = $true
		)]
		[ValidateNotNull()]
		[string]
		$Capability
	)

	$CheckBox = New-Object -TypeName System.Windows.Controls.CheckBox
	$CheckBox.Add_Click({Get-CheckboxClicked -CheckBox $_.Source})

	$TextBlock = New-Object -TypeName System.Windows.Controls.TextBlock
	$TextBlock.Text = $Capability

	$StackPanel = New-Object -TypeName System.Windows.Controls.StackPanel
	[void]$StackPanel.Children.Add($CheckBox)
	[void]$StackPanel.Children.Add($TextBlock)

	[void]$PanelContainer.Children.Add($StackPanel)

	$CheckBox.IsChecked = $false

	if ($CheckedCapabilities | Where-Object -FilterScript {$Capability -like $_})
	{
		$CheckBox.IsChecked = $true
		# If capability checked, add to the array list to remove
		# Если пакет выделен, то добавить в массив для удаления
		[void]$Capabilities.Add($Capability)
	}
}
#endregion Functions

#region Events Handlers
# Window Loaded Event
$Window.Add_Loaded({
	$OFS = "|"
	(Get-WindowsCapability -Online | Where-Object -FilterScript {($_.State -eq "Installed") -and ($_.Name -cnotmatch $ExcludedCapabilities)}).Name | ForEach-Object -Process {
		Add-CapabilityControl -Capability $_
	}
	$OFS = " "

	if ($RU)
	{
		$Window.Title = "Удалить дополнительные компоненты"
		$Button.Content = "Удалить"
	}
	else
	{
		$Window.Title = "Capabilities to Uninstall"
		$Button.Content = "Uninstall"
	}
})

# Button Click Event
$Button.Add_Click({DeleteButton})
#endregion Events Handlers

if (Get-WindowsCapability -Online | Where-Object -FilterScript {($_.State -eq "Installed") -and ($_.Name -cnotmatch ($ExcludedCapabilities -join "|"))})
{
	if ($RU)
	{
		Write-Verbose -Message "Форма открывается..." -Verbose
	}
	else
	{
		Write-Verbose -Message "Form opening..." -Verbose
	}
	# Display form
	# Отобразить форму
	$Form.ShowDialog() | Out-Null
}
else
{
	if ($RU)
	{
		Write-Verbose -Message "No capabilities to display" -Verbose
	}
	else
	{
		Write-Verbose -Message "Отсутствуют дополнительные компоненты для отображения" -Verbose
	}
}

# Turn off background apps, except the followings...
# Запретить приложениям работать в фоновом режиме, кроме следующих...
Get-ChildItem -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications | ForEach-Object -Process {
	Remove-ItemProperty -Path $_.PsPath -Name * -Force
}
$ExcludedBackgroundApps = @(
	# Lock App
	"Microsoft.LockApp*"
	# Content Delivery Manager
	"Microsoft.Windows.ContentDeliveryManager*"
	# Cortana
	"Microsoft.Windows.Cortana*"
	# Windows Search
	"Microsoft.Windows.Search*"
	# Windows Security
	# Безопасность Windows
	"Microsoft.Windows.SecHealthUI*"
	# ShellExperienceHost
	"Microsoft.Windows.ShellExperienceHost*"
	# StartMenuExperienceHost
	"Microsoft.Windows.StartMenuExperienceHost*"
	# Microsoft Store
	"Microsoft.WindowsStore*"
)
$OFS = "|"
Get-ChildItem -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications | Where-Object -FilterScript {$_.PSChildName -cnotmatch $ExcludedBackgroundApps} | ForEach-Object -Process {
	New-ItemProperty -Path $_.PsPath -Name Disabled -PropertyType DWord -Value 1 -Force
	New-ItemProperty -Path $_.PsPath -Name DisabledByUser -PropertyType DWord -Value 1 -Force
}
$OFS = " "
# Open "Background apps" page
# Открыть раздел "Фоновые приложения"
Start-Process -FilePath ms-settings:privacy-backgroundapps

# Run troubleshooters automatically, then notify
# Автоматически запускать средства устранения неполадок, а затем уведомлять
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Name AllowTelemetry -PropertyType DWord -Value 3 -Force
if (-not (Test-Path -Path HKLM:\SOFTWARE\Microsoft\WindowsMitigation))
{
	New-Item -Path HKLM:\SOFTWARE\Microsoft\WindowsMitigation -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsMitigation -Name UserPreference -PropertyType DWord -Value 3 -Force

# Turn off AutoPlay for all media and devices
# Отключить автозапуск для всех носителей и устройств
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers -Name DisableAutoplay -PropertyType DWord -Value 1 -Force

# Turn off thumbnail cache removal
# Отключить удаление кэша миниатюр
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name Autorun -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name Autorun -PropertyType DWord -Value 0 -Force

#endregion System

#region UWP apps
<#
Uninstall UWP apps
A form with the ability to select the package to remove
App packages will not be installed when new user accounts are created, if "Uninstall for All Users" checked
Add UWP apps packages names to the $UncheckedAppXPackages array list by retrieving their packages names within (Get-AppxPackage -PackageTypeFilter Bundle -AllUsers).Name command

Удалить UWP-приложения
Форма с возможностью выбрать пакет для удаления
Приложения не будут установлены при создании новых учетных записей, если отмечено "Удалять для всех пользователей"
Добавьте имена пакетов UWP-приложений в массив $UncheckedAppXPackages, получив названия их пакетов с помощью команды (Get-AppxPackage -PackageTypeFilter Bundle -AllUsers).Name
#>
Add-Type -AssemblyName PresentationCore, PresentationFramework

#region Variables
# UWP-apps array list to remove
# Массив имен UWP-приложений для удаления
$AppxPackages = New-Object -TypeName System.Collections.ArrayList($null)

# UWP-apps that won't be checked to remove by default
# UWP-приложения, которые не будут отмечены на удаление по умолчанию
$UncheckedAppxPackages = @(
	# AMD Radeon UWP panel
	# UWP-панель AMD Radeon
	"AdvancedMicroDevicesInc*"
	# iTunes
	"AppleInc.iTunes"
	# Intel UWP panel
	# UWP-панель Intel
	"AppUp.IntelGraphicsControlPanel"
	"AppUp.IntelGraphicsExperience"
	# Sticky Notes
	# Записки
	"Microsoft.MicrosoftStickyNotes"
	# Screen Sketch
	# Набросок на фрагменте экрана
	"Microsoft.ScreenSketch"
	# Photos and Video Editor
	# Фотографии и Видеоредактор
	"Microsoft.Windows.Photos"
	"Microsoft.Photos.MediaEngineDLC"
	# Calculator
	# Калькулятор
	"Microsoft.WindowsCalculator"
	# Xbox Identity Provider
	# Поставщик удостоверений Xbox
	"Microsoft.XboxIdentityProvider"
	# Xbox
	# Компаньон консоли Xbox
	"Microsoft.XboxApp"
	# Xbox TCUI
	"Microsoft.Xbox.TCUI"
	# Xbox Speech To Text Overlay
	"Microsoft.XboxSpeechToTextOverlay"
	# Xbox Game Bar
	"Microsoft.XboxGamingOverlay"
	# Xbox Game Bar Plugin
	"Microsoft.XboxGameOverlay"
	# NVIDIA Control Panel
	# Панель управления NVidia
	"NVIDIACorp.NVIDIAControlPanel"
	# Realtek Audio Console
	"RealtekSemiconductorCorp.RealtekAudioControl"
)

# UWP-apps that won't be shown in the form
# UWP-приложения, которые не будут выводиться в форме
$ExcludedAppxPackages = @(
	# Microsoft Desktop App Installer
	"Microsoft.DesktopAppInstaller"
	# Microsoft Store
	"Microsoft.StorePurchaseApp"
	"Microsoft.WindowsStore"
	# Web Media Extensions
	# Расширения для интернет-мультимедиа
	"Microsoft.WebMediaExtensions"
)
#endregion Variables

#region XAML Markup
[xml]$XAML = '
<Window
	xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
	xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
	Name="Window"
	MinHeight="450" MinWidth="400"
	SizeToContent="Width" WindowStartupLocation="CenterScreen"
	TextOptions.TextFormattingMode="Display" SnapsToDevicePixels="True"
	FontFamily="Segoe UI" FontSize="12" ShowInTaskbar="False">
	<Window.Resources>
		<Style TargetType="StackPanel">
			<Setter Property="Orientation" Value="Horizontal"/>
		</Style>
		<Style TargetType="CheckBox">
			<Setter Property="Margin" Value="10, 10, 5, 10"/>
			<Setter Property="IsChecked" Value="True"/>
		</Style>
		<Style TargetType="TextBlock">
			<Setter Property="Margin" Value="5, 10, 10, 10"/>
		</Style>
		<Style TargetType="Button">
			<Setter Property="Margin" Value="20"/>
			<Setter Property="Padding" Value="10"/>
		</Style>
	</Window.Resources>
	<Grid>
		<Grid.RowDefinitions>
			<RowDefinition Height="Auto"/>
			<RowDefinition Height="*"/>
			<RowDefinition Height="Auto"/>
		</Grid.RowDefinitions>
		<Grid Grid.Row="0">
			<Grid.ColumnDefinitions>
				<ColumnDefinition Width="*"/>
				<ColumnDefinition Width="Auto"/>
			</Grid.ColumnDefinitions>
			<StackPanel Grid.Column="1" Orientation="Horizontal">
				<CheckBox Name="CheckboxRemoveAll" IsChecked="False"/>
				<TextBlock Name="TextblockRemoveAll"/>
			</StackPanel>
		</Grid>
		<ScrollViewer Name="Scroll" Grid.Row="1"
			HorizontalScrollBarVisibility="Disabled"
			VerticalScrollBarVisibility="Auto">
			<StackPanel Name="PanelContainer" Orientation="Vertical"/>
		</ScrollViewer>
		<Button Name="Button" Grid.Row="2"/>
	</Grid>
</Window>
'
#endregion XAML Markup

$Reader = (New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $XAML)
$Form = [Windows.Markup.XamlReader]::Load($Reader)
$XAML.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object -Process {
	Set-Variable -Name ($_.Name) -Value $Form.FindName($_.Name) -Scope Global
}

#region Functions
function Get-CheckboxClicked
{
	[CmdletBinding()]
	param
	(
		[Parameter(
			Mandatory = $true,
			ValueFromPipeline = $true
		)]
		[ValidateNotNull()]
		$CheckBox
	)

	$AppxName = $CheckBox.Parent.Children[1].Text
	if ($CheckBox.IsChecked)
	{
		[void]$AppxPackages.Add($AppxName)
	}
	else
	{
		[void]$AppxPackages.Remove($AppxName)
	}
	if ($AppxPackages.Count -gt 0)
	{
		$Button.IsEnabled = $true
	}
	else
	{
		$Button.IsEnabled = $false
	}
}

function DeleteButton
{
	[void]$Window.Close()
	$OFS = "|"
	if ($CheckboxRemoveAll.IsChecked)
	{
		Get-AppxPackage -PackageTypeFilter Bundle -AllUsers | Where-Object -FilterScript {$_.Name -cmatch $AppxPackages} | Remove-AppxPackage -AllUsers -Verbose
	}
	else
	{
		Get-AppxPackage -PackageTypeFilter Bundle | Where-Object -FilterScript {$_.Name -cmatch $AppxPackages} | Remove-AppxPackage -Verbose
	}
	$OFS = " "
}

function Add-AppxControl
{
	[CmdletBinding()]
	param
	(
		[Parameter(
			Mandatory = $true,
			ValueFromPipeline = $true
		)]
		[ValidateNotNull()]
		[string]
		$AppxName
	)

	$CheckBox = New-Object -TypeName System.Windows.Controls.CheckBox
	$CheckBox.Add_Click({Get-CheckboxClicked -CheckBox $_.Source})

	$TextBlock = New-Object -TypeName System.Windows.Controls.TextBlock
	$TextBlock.Text = $AppxName

	$StackPanel = New-Object -TypeName System.Windows.Controls.StackPanel
	[void]$StackPanel.Children.Add($CheckBox)
	[void]$StackPanel.Children.Add($TextBlock)

	[void]$PanelContainer.Children.Add($StackPanel)

	if ($UncheckedAppxPackages.Contains($AppxName))
	{
		$CheckBox.IsChecked = $false
		# Exit function, item is not checked
		# Выход из функции, если элемент не выделен
		return
	}

	# If package checked, add to the array list to uninstall
	# Если пакет выделен, то добавить в массив для удаления
	[void]$AppxPackages.Add($AppxName)
}
#endregion Functions

#region Events Handlers
# Window Loaded Event
$Window.Add_Loaded({
	$OFS = "|"
	(Get-AppxPackage -PackageTypeFilter Bundle -AllUsers | Where-Object -FilterScript {$_.Name -cnotmatch $ExcludedAppxPackages}).Name | ForEach-Object -Process {
		Add-AppxControl -AppxName $_
	}
	$OFS = " "

	if ($RU)
	{
		$TextblockRemoveAll.Text = "Удалять для всех пользователей"
		$Window.Title = "Удалить UWP-приложения"
		$Button.Content = "Удалить"
	}
	else
	{
		$TextblockRemoveAll.Text = "Uninstall for All Users"
		$Window.Title = "UWP Packages to Uninstall"
		$Button.Content = "Uninstall"
	}
})

# Button Click Event
$Button.Add_Click({DeleteButton})
#endregion Events Handlers

if (Get-AppxPackage -PackageTypeFilter Bundle -AllUsers | Where-Object -FilterScript {$_.Name -cnotmatch ($ExcludedAppxPackages -join "|")})
{
	if ($RU)
	{
		Write-Verbose -Message "Форма открывается..." -Verbose
	}
	else
	{
		Write-Verbose -Message "Form opening..." -Verbose
	}
	# Display form
	# Отобразить форму
	$Form.ShowDialog() | Out-Null
}
else
{
	if ($RU)
	{
		Write-Verbose -Message "No UWP apps to display" -Verbose
	}
	else
	{
		Write-Verbose -Message "Отсутствуют UWP-приложения для отображения" -Verbose
	}
}

# Turn off Cortana autostarting
# Удалить Кортана из автозагрузки
if (Get-AppxPackage -Name Microsoft.549981C3F5F10)
{
	if (-not (Test-Path -Path "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.549981C3F5F10_8wekyb3d8bbwe\CortanaStartupId"))
	{
		New-Item -Path "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.549981C3F5F10_8wekyb3d8bbwe\CortanaStartupId" -Force
	}
	New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.549981C3F5F10_8wekyb3d8bbwe\CortanaStartupId" -Name State -PropertyType DWord -Value 1 -Force
}

#endregion UWP apps

#region Gaming
# Turn off Xbox Game Bar
# Отключить Xbox Game Bar
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR -Name AppCaptureEnabled -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path HKCU:\System\GameConfigStore -Name GameDVR_Enabled -PropertyType DWord -Value 0 -Force

# Turn off Xbox Game Bar tips
# Отключить советы Xbox Game Bar
New-ItemProperty -Path HKCU:\Software\Microsoft\GameBar -Name ShowStartupPanel -PropertyType DWord -Value 0 -Force

#endregion Gaming

#region Scheduled tasks
<#
Create a Windows cleaning up task in the Task Scheduler
The task runs every 90 days

Создать задачу в Планировщике задач по очистке Windows
Задача выполняется каждые 90 дней
#>
Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches | ForEach-Object -Process {
	Remove-ItemProperty -Path $_.PsPath -Name StateFlags1337 -Force -ErrorAction Ignore
}

$VolumeCaches = @(
	# Delivery Optimization Files
	# Файлы оптимизации доставки
	"Delivery Optimization Files",
	# Device driver packages
	# Пакеты драйверов устройств
	"Device Driver Packages",
	# Previous Windows Installation(s)
	# Предыдущие установки Windows
	"Previous Installations",
	# Файлы журнала установки
	"Setup Log Files",
	# Temporary Setup Files
	"Temporary Setup Files",
	# Microsoft Defender Antivirus
	"Windows Defender",
	# Windows upgrade log files
	# Файлы журнала обновления Windows
	"Windows Upgrade Log Files"
)
foreach ($VolumeCache in $VolumeCaches)
{
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\$VolumeCache" -Name StateFlags1337 -PropertyType DWord -Value 2 -Force
}

$PS1Script = '
$app = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cleanmgr.exe"

[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
$Template = [Windows.UI.Notifications.ToastTemplateType]::ToastImageAndText01
[xml]$ToastTemplate = ([Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($Template).GetXml())

if ($PSUICulture -eq "ru-RU")
{
	[xml]$ToastTemplate = @"
<toast launch="app-defined-string">
	<visual>
		<binding template="ToastGeneric">
			<text>Очистка неиспользуемых файлов и обновлений Windows начнется через минуту</text>
		</binding>
	</visual>
	<actions>
	<action activationType="background" content="Хорошо" arguments="later"/>
	</actions>
</toast>
"@
}
else
{
	[xml]$ToastTemplate = @"
<toast launch="app-defined-string">
	<visual>
		<binding template="ToastGeneric">
			<text>Cleaning up unused Windows files and updates start in a minute</text>
		</binding>
	</visual>
	<actions>
		<action activationType="background" content="OK" arguments="later"/>
	</actions>
</toast>
"@
}

$ToastXml = New-Object -TypeName Windows.Data.Xml.Dom.XmlDocument
$ToastXml.LoadXml($ToastTemplate.OuterXml)

[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show($ToastXml)

Start-Sleep -Seconds 60

# Process startup info
# Параметры запуска процесса
$ProcessInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
$ProcessInfo.FileName = "$env:SystemRoot\system32\cleanmgr.exe"
$ProcessInfo.Arguments = "/sagerun:1337"
$ProcessInfo.UseShellExecute = $true
$ProcessInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Minimized

# Process object using the startup info
# Объект процесса, используя заданные параметры
$Process = New-Object System.Diagnostics.Process
$Process.StartInfo = $ProcessInfo

# Start the process
# Запуск процесса
$Process.Start() | Out-Null

Start-Sleep -Seconds 3
$SourceMainWindowHandle = (Get-Process -Name cleanmgr).MainWindowHandle

function MinimizeWindow
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		$Process
	)

	$ShowWindowAsync = @{
	Namespace = "WinAPI"
	Name = "Win32ShowWindowAsync"
	Language = "CSharp"
	MemberDefinition = @"
[DllImport("user32.dll")]
public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
"@
	}
	if (-not ("WinAPI.Win32ShowWindowAsync" -as [type]))
	{
		Add-Type @ShowWindowAsync
	}

	$MainWindowHandle = (Get-Process -Name $Process).MainWindowHandle
	[WinAPI.Win32ShowWindowAsync]::ShowWindowAsync($MainWindowHandle, 2)
}

while ($true)
{
	$CurrentMainWindowHandle = (Get-Process -Name cleanmgr).MainWindowHandle
	if ([int]$SourceMainWindowHandle -ne [int]$CurrentMainWindowHandle)
	{
		MinimizeWindow -Process cleanmgr
		break
	}
	Start-Sleep -Milliseconds 5
}

$ProcessInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
# Cleaning up unused updates
# Очистка неиспользованных обновлений
$ProcessInfo.FileName = "$env:SystemRoot\system32\dism.exe"
$ProcessInfo.Arguments = "/Online /English /Cleanup-Image /StartComponentCleanup /NoRestart"
$ProcessInfo.UseShellExecute = $true
$ProcessInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Minimized

# Process object using the startup info
# Объект процесса, используя заданные параметры
$Process = New-Object System.Diagnostics.Process
$Process.StartInfo = $ProcessInfo

# Start the process
# Запуск процесса
$Process.Start() | Out-Null
'
$EncodedScript = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($PS1Script))

$Action = New-ScheduledTaskAction -Execute powershell.exe -Argument "-WindowStyle Hidden -EncodedCommand $EncodedScript"
$Trigger = New-ScheduledTaskTrigger -Daily -DaysInterval 90 -At 9am
$Settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
$Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest
if ($RU)
{
	$Description =
	"Очистка неиспользуемых файлов и обновлений Windows, используя встроенную программу Очистка диска. Чтобы расшифровать закодированную строку используйте [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(`"строка`"))"
}
else
{
	$Description =
	"Cleaning up unused Windows files and updates using built-in Disk cleanup app. To decode encoded command use [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(`"string`"))"
}
$Parameters = @{
	"TaskName"		= "Windows Cleanup"
	"TaskPath"		= "Setup Script"
	"Principal"		= $Principal
	"Action"		= $Action
	"Description"	= $Description
	"Settings"		= $Settings
	"Trigger"		= $Trigger
}
Register-ScheduledTask @Parameters -Force

<#
Create a task in the Task Scheduler to clear the %SystemRoot%\SoftwareDistribution\Download folder
The task runs on Thursdays every 4 weeks

Создать задачу в Планировщике задач по очистке папки %SystemRoot%\SoftwareDistribution\Download
Задача выполняется по четвергам каждую 4 неделю
#>
$Argument = "
	(Get-Service -Name wuauserv).WaitForStatus('Stopped', '01:00:00')
	Get-ChildItem -Path $env:SystemRoot\SoftwareDistribution\Download -Recurse -Force | Remove-Item -Recurse -Force
"
$Action = New-ScheduledTaskAction -Execute powershell.exe -Argument $Argument
$Trigger = New-JobTrigger -Weekly -WeeksInterval 4 -DaysOfWeek Thursday -At 9am
$Settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest
if ($RU)
{
	$Description = "Очистка папки %SystemRoot%\SoftwareDistribution\Download"
}
else
{
	$Description = "The %SystemRoot%\SoftwareDistribution\Download folder cleaning"
}
$Parameters = @{
	"TaskName"		= "SoftwareDistribution"
	"TaskPath"		= "Setup Script"
	"Principal"		= $Principal
	"Action"		= $Action
	"Description"	= $Description
	"Settings"		= $Settings
	"Trigger"		= $Trigger
}
Register-ScheduledTask @Parameters -Force

<#
Create a task in the Task Scheduler to clear the %TEMP% folder
The task runs every 62 days

Создать задачу в Планировщике задач по очистке папки %TEMP%
Задача выполняется каждые 62 дня
#>
$Argument = "Get-ChildItem -Path $env:TEMP -Force -Recurse | Remove-Item -Force -Recurse"
$Action = New-ScheduledTaskAction -Execute powershell.exe -Argument $Argument
$Trigger = New-ScheduledTaskTrigger -Daily -DaysInterval 62 -At 9am
$Settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest
if ($RU)
{
	$Description = "Очистка папки %TEMP%"
}
else
{
	$Description = "The %TEMP% folder cleaning"
}
$Parameters = @{
	"TaskName"		= "Temp"
	"TaskPath"		= "Setup Script"
	"Principal"		= $Principal
	"Action"		= $Action
	"Description"	= $Description
	"Settings"		= $Settings
	"Trigger"		= $Trigger
}
Register-ScheduledTask @Parameters -Force
#endregion Scheduled tasks

#region Microsoft Defender & Security
# Turn on Controlled folder access and add protected folders
# Включить контролируемый доступ к папкам и добавить защищенные папки
if ($RU)
{
	$Title = "Контролируемый доступ к папкам"
	$Message = "Чтобы включить контролируемый доступ к папкам и добавить папку в список защищенных, введите необходимую букву"
	$Options = "&Добавить защищенную папку", "&Пропустить"
}
else
{
	$Title = "Controlled folder access"
	$Message = "To turn on Controlled folder access and add protected folder enter the required letter"
	$Options = "&Add a protected folder", "&Skip"
}
$DefaultChoice = 1

do
{
	$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)
	switch ($Result)
	{
		"0"
		{
			Add-Type -AssemblyName System.Windows.Forms
			$FolderBrowserDialog = New-Object -TypeName System.Windows.Forms.FolderBrowserDialog
			if ($RU)
			{
				$FolderBrowserDialog.Description = "Выберите папку"
			}
			else
			{
				$FolderBrowserDialog.Description = "Select a folder"
			}
			$FolderBrowserDialog.RootFolder = "MyComputer"
			# Focus on open file dialog
			# Перевести фокус на диалог открытия файла
			$tmp = New-Object -TypeName System.Windows.Forms.Form -Property @{TopMost = $true}
			$FolderBrowserDialog.ShowDialog($tmp)
			if ($FolderBrowserDialog.SelectedPath)
			{
				Set-MpPreference -EnableControlledFolderAccess Enabled
				Add-MpPreference -ControlledFolderAccessProtectedFolders $FolderBrowserDialog.SelectedPath -Force
			}
		}
		"1"
		{
			if ($RU)
			{
				Write-Verbose -Message "Пропущено" -Verbose
			}
			else
			{
				Write-Verbose -Message "Skipped" -Verbose
			}
		}
	}
}
until ($Result -eq 1)

# Allow an app through Controlled folder access
# Разрешить работу приложения через контролируемый доступ к папкам
if ((Get-MpPreference).EnableControlledFolderAccess -eq 1)
{
	if ($RU)
	{
		$Title = "Контролируемый доступ к папкам"
		$Message = "Чтобы разрешить работу приложения через контролируемый доступ к папкам, введите необходимую букву"
		$Options = "&Добавить разрешенное приложение", "&Пропустить"
	}
	else
	{
		$Title = "Controlled folder access"
		$Message = "To allow an app through Controlled folder access enter the required letter"
		$Options = "&Add a protected folder", "&Skip"
	}
	$DefaultChoice = 1

	do
	{
		$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)
		switch ($Result)
		{
			"0"
			{
				Add-Type -AssemblyName System.Windows.Forms
				$OpenFileDialog = New-Object -TypeName System.Windows.Forms.OpenFileDialog
				if ($RU)
				{
					$OpenFileDialog.Filter = "*.exe|*.exe|Все файлы (*.*)|*.*"
				}
				else
				{
					$OpenFileDialog.Filter = "*.exe|*.exe|All Files (*.*)|*.*"
				}
				$OpenFileDialog.InitialDirectory = "::{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
				$OpenFileDialog.Multiselect = $false
				# Focus on open file dialog
				# Перевести фокус на диалог открытия файла
				$tmp = New-Object -TypeName System.Windows.Forms.Form -Property @{TopMost = $true}
				$OpenFileDialog.ShowDialog($tmp)
				if ($OpenFileDialog.FileName)
				{
					Add-MpPreference -ControlledFolderAccessAllowedApplications $OpenFileDialog.FileName -Force
				}
			}
			"1"
			{
				if ($RU)
				{
					Write-Verbose -Message "Пропущено" -Verbose
				}
				else
				{
					Write-Verbose -Message "Skipped" -Verbose
				}
			}
		}
	}
	until ($Result -eq 1)
}

# Add exclusion folder from Microsoft Defender Antivirus scanning
# Добавить папку в список исключений сканирования Microsoft Defender
if ($RU)
{
	$Title = "Microsoft Defender"
	$Message = "Чтобы исключить папку из списка сканирования антивредоносной программы Microsoft Defender, введите необходимую букву"
	$Options = "&Исключить папку", "&Пропустить"
}
else
{
	$Title = "Microsoft Defender"
	$Message = "To exclude folder from Microsoft Defender Antivirus Scan enter the required letter"
	$Options = "&Exclude folder", "&Skip"
}
$DefaultChoice = 1

do
{
	$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)
	switch ($Result)
	{
		"0"
		{
			Add-Type -AssemblyName System.Windows.Forms
			$FolderBrowserDialog = New-Object -TypeName System.Windows.Forms.FolderBrowserDialog
			if ($RU)
			{
				$FolderBrowserDialog.Description = "Выберите папку"
			}
			else
			{
				$FolderBrowserDialog.Description = "Select a folder"
			}
			$FolderBrowserDialog.RootFolder = "MyComputer"
			# Focus on open file dialog
			# Перевести фокус на диалог открытия файла
			$tmp = New-Object -TypeName System.Windows.Forms.Form -Property @{TopMost = $true}
			$FolderBrowserDialog.ShowDialog($tmp)
			if ($FolderBrowserDialog.SelectedPath)
			{
				Add-MpPreference -ExclusionPath $FolderBrowserDialog.SelectedPath -Force
			}
		}
		"1"
		{
			if ($RU)
			{
				Write-Verbose -Message "Пропущено" -Verbose
			}
			else
			{
				Write-Verbose -Message "Skipped" -Verbose
			}
		}
	}
}
until ($Result -eq 1)

# Add exclusion file from Microsoft Defender Antivirus scanning
# Добавить файл в список исключений сканирования Microsoft Defender
if ($RU)
{
	$Title = "Microsoft Defender"
	$Message = "Чтобы исключить файл из списка сканирования антивредоносной программы Microsoft Defender, введите необходимую букву"
	$Options = "&Исключить файл", "&Пропустить"
}
else
{
	$Title = "Microsoft Defender"
	$Message = "To exclude file from Microsoft Defender Antivirus Scan enter the required letter"
	$Options = "&Exclude file", "&Skip"
}
$DefaultChoice = 1

do
{
	$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)
	switch ($Result)
	{
		"0"
		{
			Add-Type -AssemblyName System.Windows.Forms
			$OpenFileDialog = New-Object -TypeName System.Windows.Forms.OpenFileDialog
			if ($RU)
			{
				$OpenFileDialog.Filter = "Все файлы (*.*)|*.*"
			}
			else
			{
				$OpenFileDialog.Filter = "All Files (*.*)|*.*"
			}
			$OpenFileDialog.InitialDirectory = "::{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
			$OpenFileDialog.Multiselect = $false
			# Focus on open file dialog
			# Перевести фокус на диалог открытия файла
			$tmp = New-Object -TypeName System.Windows.Forms.Form -Property @{TopMost = $true}
			$OpenFileDialog.ShowDialog($tmp)
			if ($OpenFileDialog.FileName)
			{
				Add-MpPreference -ExclusionPath $OpenFileDialog.FileName -Force
			}
		}
		"1"
		{
			if ($RU)
			{
				Write-Verbose -Message "Пропущено" -Verbose
			}
			else
			{
				Write-Verbose -Message "Skipped" -Verbose
			}
		}
	}
}
until ($Result -eq 1)

# Turn on Microsoft Defender Exploit Guard network protection
# Включить защиту сети в Microsoft Defender Exploit Guard
Set-MpPreference -EnableNetworkProtection Enabled

# Turn on detection for potentially unwanted applications and block them
# Включить обнаружение потенциально нежелательных приложений и блокировать их
Set-MpPreference -PUAProtection Enabled

# Run Microsoft Defender within a sandbox
# Запускать Microsoft Defender в песочнице
setx /M MP_FORCE_USE_SANDBOX 1

# Dismiss Microsoft Defender offer in the Windows Security about signing in Microsoft account
# Отклонить предложение Microsoft Defender в "Безопасность Windows" о входе в аккаунт Microsoft
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Security Health\State" -Name AccountProtection_MicrosoftAccount_Disconnected -PropertyType DWord -Value 1 -Force

# Dismiss Microsoft Defender offer in the Windows Security about to turn on the SmartScreen filter for Microsoft Edge
# Отклонить предложение Windows Defender в "Безопасность Windows" включить фильтр SmartScreen для Microsoft Edge
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Security Health\State" -Name AppAndBrowser_EdgeSmartScreenOff -PropertyType DWord -Value 0 -Force

# Turn on events auditing generated when a process is created or starts
# Включить аудит событий, возникающих при создании или запуске процесса
auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable

<#
Include command line in process creation events
In order this feature to work events auditing must be enabled

Включать командную строку в событиях создания процесса
Необходимо включить аудит событий, чтобы работала данная опция
#>
if ($RU)
{
	$OutputEncoding = [System.Console]::OutputEncoding = [System.Console]::InputEncoding = [System.Text.Encoding]::UTF8
}
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit -Name ProcessCreationIncludeCmdLine_Enabled -PropertyType DWord -Value 1 -Force

<#
Create "Process Creation" Event Viewer Custom View
In order this feature to work events auditing and command line in process creation events must be enabled

Создать настаиваемое представление "Создание процесса" в Просмотре событий
Необходимо включить аудит событий и командную строку в событиях создания процесса, чтобы работала данная опция
#>
$XML = @"
<ViewerConfig>
	<QueryConfig>
		<QueryParams>
			<UserQuery />
		</QueryParams>
		<QueryNode>
			<Name>Process Creation</Name>
			<Description>Process Creation and Command-line Auditing Events</Description>
			<QueryList>
				<Query Id="0" Path="Security">
					<Select Path="Security">*[System[(EventID=4688)]]</Select>
				</Query>
			</QueryList>
		</QueryNode>
	</QueryConfig>
</ViewerConfig>
"@
if (-not (Test-Path -Path "$env:ProgramData\Microsoft\Event Viewer\Views"))
{
	New-Item -Path "$env:ProgramData\Microsoft\Event Viewer\Views" -ItemType Directory -Force
}
$ProcessCreationFilePath = "$env:ProgramData\Microsoft\Event Viewer\Views\ProcessCreation.xml"
# Saving ProcessCreation.xml in UTF-8 encoding
# Сохраняем ProcessCreation.xml в кодировке UTF-8
Set-Content -Value (New-Object System.Text.UTF8Encoding).GetBytes($XML) -Encoding Byte -Path $ProcessCreationFilePath -Force

if ($RU)
{
	[xml]$XML = Get-Content -Path $ProcessCreationFilePath
	$XML.ViewerConfig.QueryConfig.QueryNode.Name = "Создание процесса"
	$XML.ViewerConfig.QueryConfig.QueryNode.Description = "События содания нового процесса и аудит командной строки"
	$xml.Save("$env:ProgramData\Microsoft\Event Viewer\Views\ProcessCreation.xml")
}

# Turn on logging for all Windows PowerShell modules
# Включить ведение журнала для всех модулей Windows PowerShell
if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging -Name EnableModuleLogging -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames -Name * -PropertyType String -Value * -Force

# Turn on logging of all PowerShell script input to the Windows PowerShell event log
# Включить регистрацию всех вводимых сценариев PowerShell в журнале событий Windows PowerShell
if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -PropertyType DWord -Value 1 -Force

# Turn off SmartScreen for apps and files
# Отключить SmartScreen для приложений и файлов
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name SmartScreenEnabled -PropertyType String -Value Off -Force

# Turn off Windows Script Host
# Отключить Windows Script Host
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name Enabled -PropertyType DWord -Value 0 -Force
#endregion Microsoft Defender & Security

#region Context menu
# Add the "Extract" item to Windows Installer (.msi) context menu
# Добавить пункт "Извлечь" в контекстное меню Windows Installer (.msi)
if (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command))
{
	New-Item -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command -Force
}
$Value = "{0}" -f 'msiexec.exe /a "%1" /qb TARGETDIR="%1 extracted"'
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command -Name "(Default)" -PropertyType String -Value $Value -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract -Name MUIVerb -PropertyType String -Value "@shell32.dll,-31382" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract -Name Icon -PropertyType String -Value "shell32.dll,-16817" -Force

# Add the "Install" item to the .cab archives context menu
# Добавить пункт "Установить" в контекстное меню .cab архивов
if (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs\Command))
{
	New-Item -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs\Command -Force
}
$Value = "{0}" -f "cmd /c DISM.exe /Online /Add-Package /PackagePath:`"%1`" /NoRestart & pause"
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs\Command -Name "(Default)" -PropertyType String -Value $Value -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs -Name MUIVerb -PropertyType String -Value "@shell32.dll,-10210" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs -Name HasLUAShield -PropertyType String -Value "" -Force

# Add the "Run as different user" item to the .exe files types context menu
# Добавить "Запуск от имени другого пользователя" в контекстное меню .exe файлов
Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\exefile\shell\runasuser -Name Extended -Force -ErrorAction Ignore

# Hide the "Cast to Device" item from the context menu
# Скрыть пункт "Передать на устройство" из контекстного меню
if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"))
{
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Force
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" -PropertyType String -Value "Play to menu" -Force

# Hide the "Share" item from the context menu
# Скрыть пункт "Отправить" (поделиться) из контекстного меню
if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"))
{
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Force
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{E2BF9676-5F8F-435C-97EB-11607A5BEDF7}" -PropertyType String -Value "" -Force

# Hide the "Edit with Paint 3D" item from the context menu
# Скрыть пункт "Изменить с помощью Paint 3D" из контекстного меню
$extensions = @(".bmp", ".gif", ".jpe", ".jpeg", ".jpg", ".png", ".tif", ".tiff")
foreach ($extension in $extensions)
{
	New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\$extension\Shell\3D Edit" -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
}

# Hide the "Edit with Photos" item from the context menu
# Скрыть пункт "Изменить с помощью приложения "Фотографии"" из контекстного меню
if (Get-AppxPackage -Name Microsoft.Windows.Photos)
{
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
}

# Hide the "Create a new video" item from the context menu
# Скрыть пункт "Создать новое видео" из контекстного меню
if (Get-AppxPackage -Name Microsoft.Windows.Photos)
{
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellCreateVideo -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
}

# Hide the "Edit" item from the images context menu
# Скрыть пункт "Изменить" из контекстного меню изображений
if ((Get-WindowsCapability -Online -Name "Microsoft.Windows.MSPaint*").State -eq "Installed")
{
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\image\shell\edit -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
}

# Hide the "Print" item from the .bat and .cmd context menu
# Скрыть пункт "Печать" из контекстного меню .bat и .cmd файлов
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\batfile\shell\print -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\cmdfile\shell\print -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force

# Hide the "Include in Library" item from the context menu
# Скрыть пункт "Добавить в библиотеку" из контекстного меню
New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\Library Location" -Name "(Default)" -PropertyType String -Value "-{3dad6c5d-2167-4cae-9914-f99e41c12cfa}" -Force

# Hide the "Send to" item from the folders context menu
# Скрыть пункт "Отправить" из контекстного меню папок
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo -Name "(Default)" -PropertyType String -Value "-{7BA4C740-9E81-11CF-99D3-00AA004AE837}" -Force

# Hide the "Turn on BitLocker" item from the context menu
# Скрыть пункт "Включить BitLocker" из контекстного меню
if (Get-WindowsEdition -Online | Where-Object -FilterScript {$_.Edition -eq "Professional" -or $_.Edition -eq "Enterprise"})
{
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\encrypt-bde -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\encrypt-bde-elev -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\manage-bde -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\resume-bde -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\resume-bde-elev -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Drive\shell\unlock-bde -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
}

# Remove the "Bitmap image" item from the "New" context menu
# Удалить пункт "Точечный рисунок" из контекстного меню "Создать"
if ((Get-WindowsCapability -Online -Name "Microsoft.Windows.MSPaint*").State -eq "Installed")
{
	Remove-Item -Path Registry::HKEY_CLASSES_ROOT\.bmp\ShellNew -Force -ErrorAction Ignore
}

# Remove the "Rich Text Document" item from the "New" context menu
# Удалить пункт "Документ в формате RTF" из контекстного меню "Создать"
if ((Get-WindowsCapability -Online -Name "Microsoft.Windows.WordPad*").State -eq "Installed")
{
	Remove-Item -Path Registry::HKEY_CLASSES_ROOT\.rtf\ShellNew -Force -ErrorAction Ignore
}

# Remove the "Compressed (zipped) Folder" item from the "New" context menu
# Удалить пункт "Сжатая ZIP-папка" из контекстного меню "Создать"
Remove-Item -Path Registry::HKEY_CLASSES_ROOT\.zip\CompressedFolder\ShellNew -Force -ErrorAction Ignore

# Make the "Open", "Print", "Edit" context menu items available, when more than 15 items selected
# Сделать доступными элементы контекстного меню "Открыть", "Изменить" и "Печать" при выделении более 15 элементов
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name MultipleInvokePromptMinimum -PropertyType DWord -Value 300 -Force

# Hide the "Look for an app in the Microsoft Store" item in "Open with" dialog
# Скрыть пункт "Поиск приложения в Microsoft Store" в диалоге "Открыть с помощью"
if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -PropertyType DWord -Value 1 -Force

# Hide the "Previous Versions" tab from files and folders context menu and the "Restore previous versions" context menu item
# Скрыть вкладку "Предыдущие версии" в свойствах файлов и папок и пункт контекстного меню "Восстановить прежнюю версию"
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name NoPreviousVersionsPage -PropertyType DWord -Value 1 -Force
#endregion Context menu

#region Refresh
$UpdateExplorer = @{
	Namespace = "WinAPI"
	Name = "UpdateExplorer"
	Language = "CSharp"
	MemberDefinition = @"
private static readonly IntPtr HWND_BROADCAST = new IntPtr(0xffff);
private const int WM_SETTINGCHANGE = 0x1a;
private const int SMTO_ABORTIFHUNG = 0x0002;

[DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = false)]
static extern bool SendNotifyMessage(IntPtr hWnd, uint Msg, IntPtr wParam, string lParam);
[DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = false)]
private static extern IntPtr SendMessageTimeout(IntPtr hWnd, int Msg, IntPtr wParam, string lParam, int fuFlags, int uTimeout, IntPtr lpdwResult);
[DllImport("shell32.dll", CharSet = CharSet.Auto, SetLastError = false)]
private static extern int SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);
public static void Refresh()
{
	// Update desktop icons
	// Обновить иконки рабочего стола
	SHChangeNotify(0x8000000, 0x1000, IntPtr.Zero, IntPtr.Zero);
	// Update environment variables
	// Обновить переменные среды
	SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, IntPtr.Zero, null, SMTO_ABORTIFHUNG, 100, IntPtr.Zero);
	// Update taskbar
	// Обновить панель задач
	SendNotifyMessage(HWND_BROADCAST, WM_SETTINGCHANGE, IntPtr.Zero, "TraySettings");
}

private static readonly IntPtr hWnd = new IntPtr(65535);
private const int Msg = 273;
// Virtual key ID of the F5 in File Explorer
// Виртуальный код клавиши F5 в проводнике
private static readonly UIntPtr UIntPtr = new UIntPtr(41504);

[DllImport("user32.dll", SetLastError=true)]
public static extern int PostMessageW(IntPtr hWnd, uint Msg, UIntPtr wParam, IntPtr lParam);
public static void PostMessage()
{
	// F5 pressing simulation to refresh the desktop
	// Симуляция нажатия F5 для обновления рабочего стола
	PostMessageW(hWnd, Msg, UIntPtr, IntPtr.Zero);
}
"@
}
if (-not ("WinAPI.UpdateExplorer" -as [type]))
{
	Add-Type @UpdateExplorer
}

# Send F5 pressing simulation to refresh the desktop
# Симулировать нажатие F5 для обновления рабочего стола
[WinAPI.UpdateExplorer]::PostMessage()
# Refresh desktop icons, environment variables, taskbar
# Обновить иконки рабочего стола, переменные среды, панель задач
[WinAPI.UpdateExplorer]::Refresh()

# Restart the Start menu
# Перезапустить меню "Пуск"
Stop-Process -Name StartMenuExperienceHost -Force
#endregion Refresh

# Errors output
# Вывод ошибок
if ($Error)
{
	($Error | ForEach-Object -Process {
		if ($RU)
		{
			[PSCustomObject] @{
				Строка = $_.InvocationInfo.ScriptLineNumber
				"Ошибки/предупреждения" = $_.Exception.Message
			}
		}
		else
		{
			[PSCustomObject] @{
				Line = $_.InvocationInfo.ScriptLineNumber
				"Errors/Warnings" = $_.Exception.Message
			}
		}
	} | Sort-Object -Property Line | Format-Table -AutoSize -Wrap | Out-String).Trim()
}