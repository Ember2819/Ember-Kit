import asyncio
import aiohttp
import ssl
import time
import certifi
import random
from rich.table import Table
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
def socialsSniper():
    console = Console()

    async def check_platform(session, semaphore, name, url_template, username, validator, progress, task_id):
        usernames = list(dict.fromkeys([username, username.lower()]))
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"}
        
        found_url = "-"
        status = "[dim red]Not Found[/dim red]"

        for u in usernames:
            url = url_template.format(u)
            
            async with semaphore:
                await asyncio.sleep(random.uniform(0.1, 0.3))
                
                try:
                    async with session.get(url, timeout=5, allow_redirects=True, headers=headers) as response:
                        text = await response.text()
                        if response.status == 200 and not any(k.lower() in text.lower() for k in validator):
                            status = "[bold green]FOUND[/bold green]"
                            found_url = url
                            break 
                except Exception:
                    continue
            
            if "FOUND" in status:
                break
                
        progress.update(task_id, advance=1)
        return name, status, found_url

    async def run_sniper(target_username):
        platforms = {
            "Twitter/X": ("https://x.com/{}", ["does not exist", "not found", "This account doesn't exist"]),
            "Instagram": ("https://www.instagram.com/{}/", ["doesn't exist", "Login", "user not found"]),
            "TikTok": ("https://www.tiktok.com/@{}", ["Couldn't find this account", "not found"]),
            "Facebook": ("https://www.facebook.com/{}", ["Page Not Found", "This page isn't available", "content unavailable"]),
            "Snapchat": ("https://www.snapchat.com/add/{}", ["not found", "user not found"]),
            "YouTube": ("https://www.youtube.com/@{}", ["This page doesn't exist", "404", "not found"]),

            "Reddit": ("https://www.reddit.com/user/{}", ["page not found", "GeneralError", "does not exist"]),
            "Discord": ("https://discord.com/users/{}", ["Not found", "404", "doesn't exist"]),
            "Telegram": ("https://t.me/{}", ["If you have Telegram installed", "user not found"]),

            "Medium": ("https://medium.com/@{}", ["not found", "404", "doesn't exist"]),
            "Tumblr": ("https://{}.tumblr.com", ["not found", "404", "doesn't exist"]),
            "Substack": ("https://substack.com/@{}", ["not found", "doesn't exist"]),
            "Hashnode": ("https://hashnode.com/@{}", ["not found", "404"]),
            "DEV Community": ("https://dev.to/{}", ["Not Found", "404"]),
            "Wattpad": ("https://www.wattpad.com/{}", ["doesn't exist", "not found", "404"]),

            "LinkedIn": ("https://www.linkedin.com/in/{}/", ["doesn't exist", "404", "not found"]),
            "GitHub": ("https://github.com/{}", ["Not Found", "404"]),
            "GitLab": ("https://gitlab.com/{}", ["Sign in", "404", "not found"]),
            "Stack Overflow": ("https://stackoverflow.com/users/{}", ["does not exist", "not found", "404"]),

            "Replit": ("https://replit.com/@{}", ["not found", "404", "doesn't exist"]),
            "CodePen": ("https://codepen.io/{}", ["Page Not Found", "404", "not found"]),
            "Behance": ("https://www.behance.net/{}", ["Page not found", "404"]),
            "ArtStation": ("https://www.artstation.com/{}", ["Page not found", "404", "doesn't exist"]),
            "Dribbble": ("https://dribbble.com/{}", ["Page not found", "404"]),

            "Twitch": ("https://www.twitch.tv/{}", ["content is unavailable", "404", "not found"]),
            "Steam": ("https://steamcommunity.com/profiles/{}", ["Error - Account Not Found", "404"]),
            "Epic Games": ("https://www.epicgames.com/site/en-US/community/{}", ["Page Not Found", "404"]),
            "Chess.com": ("https://www.chess.com/member/{}", ["not found", "404", "Member not found"]),
            "MyAnimeList": ("https://myanimelist.net/profile/{}", ["does not exist", "404", "not found"]),
            "Trakt": ("https://trakt.tv/users/{}", ["not found", "404"]),

            "SoundCloud": ("https://soundcloud.com/{}", ["not found", "404", "doesn't exist"]),
            "Spotify": ("https://open.spotify.com/user/{}", ["not found", "404"]),
            "Last.fm": ("https://www.last.fm/user/{}", ["not found", "404"]),
            "Bandcamp": ("https://{}.bandcamp.com", ["not found", "404"]),

            "Flickr": ("https://www.flickr.com/photos/{}", ["not found", "404"]),
            "Pinterest": ("https://www.pinterest.com/{}/", ["404", "doesn't exist", "not found"]),

            "IMDb": ("https://www.imdb.com/user/{}/", ["not found", "404"]),
            "Goodreads": ("https://www.goodreads.com/{}", ["not found", "404", "doesn't exist"]),

            "Patreon": ("https://www.patreon.com/{}", ["not found", "404", "doesn't exist"]),
            "Ko-fi": ("https://ko-fi.com/{}", ["not found", "404"]),
            "Fiverr": ("https://www.fiverr.com/{}", ["not found", "404", "doesn't exist"]),
            "Upwork": ("https://www.upwork.com/freelancers/~{}", ["not found", "404"]),

            "Linktree": ("https://linktr.ee/{}", ["doesn't exist", "404", "not found"]),
            "Mastodon": ("https://mastodon.social/@{}", ["not found", "404"]),
            "Bluesky": ("https://bsky.app/profile/{}", ["not found", "404", "doesn't exist"]),
            "Quora": ("https://www.quora.com/profile/{}", ["not found", "404"]),
            "Amino": ("https://aminoapps.com/c/{}", ["not found", "404"]),
            "Letterboxd": ("https://letterboxd.com/{}/", ["not found", "404", "doesn't exist"]),
        }
        semaphore = asyncio.Semaphore(10)

        ssl_context = ssl.create_default_context(cafile=certifi.where())

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(bar_width=40, pulse_style="cyan"), TaskProgressColumn(), console=console) as progress:
            main_task = progress.add_task(f"[cyan]Sniping {target_username}...", total=len(platforms))
            
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_context)) as session:
                tasks = [check_platform(session, semaphore, n, u, target_username, k, progress, main_task) for n, (u, k) in platforms.items()]
                results = await asyncio.gather(*tasks)

        table = Table(title=f"EmberKit Social Sniper: {target_username}", header_style="bold magenta")
        table.add_column("Platform", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Profile URL")

        for res in results:
            table.add_row(*res)
        console.print("\n", table)

    logo = """
    █████████                     ███            ████         
    ███░░░░░███                   ░░░            ░░███         
    ░███    ░░░   ██████   ██████  ████   ██████   ░███   █████ 
    ░░█████████  ███░░███ ███░░███░░███  ░░░░░███  ░███  ███░░  
    ░░░░░░░░███░███ ░███░███ ░░░  ░███   ███████  ░███ ░░█████ 
    ███    ░███░███ ░███░███  ███ ░███  ███░░███  ░███  ░░░░███
    ░░█████████ ░░██████ ░░██████  █████░░████████ █████ ██████ 
    ░░░░░░░░░   ░░░░░░   ░░░░░░  ░░░░░  ░░░░░░░░ ░░░░░ ░░░░░░  
                                                                
                                                                
                                                                
    █████████              ███                                
    ███░░░░░███            ░░░                                 
    ░███    ░░░  ████████   ████  ████████   ██████  ████████   
    ░░█████████ ░░███░░███ ░░███ ░░███░░███ ███░░███░░███░░███  
    ░░░░░░░░███ ░███ ░███  ░███  ░███ ░███░███████  ░███ ░░░   
    ███    ░███ ░███ ░███  ░███  ░███ ░███░███░░░   ░███       
    ░░█████████  ████ █████ █████ ░███████ ░░██████  █████      
    ░░░░░░░░░  ░░░░ ░░░░░ ░░░░░  ░███░░░   ░░░░░░  ░░░░░       
                                ░███                          
                                █████                         
                                ░░░░░                        
    """
    console.print(logo, style="bold red")
    time.sleep(1)
    console.print("[cyan]This program searches popular social media platforms for a given username. \nUse ethically and do not use it on usernames you do not have permission to search for.[/cyan]")
    console.print("[cyan]This program may be blocked by some platforms and return false negatives. \nTake all output with a grain of salt.[/cyan]")
    console.print("[bold red]Disclaimer: Use this tool responsibly and at your own risk.[/bold red]")
    time.sleep(4)
    query = console.input("[bold yellow]Enter Username > [/bold yellow]").strip()
    if query:
        asyncio.run(run_sniper(query))
