/*
This script continously loads post as the user scrolls the page. It uses the IntersectionObserver API to detect when the last post is in view. When the last post is in view, it fetches the next page and appends the posts to the page. It then checks if there is a next page and if there is, it continues to observe the last post. If there is no next page, it disconnects the observer. 

Importantly, for this script to work, it requires that each card have the `post` class and that the card container have the `gh-postfeed` class
*/

let link = document.querySelector('link[rel="next"]')?.getAttribute('href');

// Fetch and parse next page
async function getNextPage(url) {
    try {
        const res = await fetch(url);
        
        if (!res.ok) {
            throw new Error('Failed to fetch page')
        }
        
        const nextPageHtml = await res.text();
        const parser = new DOMParser();
        const parsed = parser.parseFromString(nextPageHtml, 'text/html');
        const posts = parsed.querySelectorAll('.post');
        const nextLink = parsed.querySelector('link[rel="next"]')?.getAttribute('href');
        
        return {posts, nextLink}

    } catch (error) {
        throw new Error(error)
    }
}

export default function infiniteScroll() {
    
    if (!link) { return; }

    const options = {
        // When the last card is within a 150px of the viewport, fetch the next page. This provides a smoother transition between pages 
       rootMargin: '150px',
    }

    const callback = (entries, observer) => {
        try {
            entries.forEach(entry => {
            
                if (entry.isIntersecting) {
                    
                    if (link) {
                        getNextPage(link).then(({posts, nextLink}) => {
                            posts.forEach(post => {
                                document.querySelector('.gh-postfeed').append(post)
                            })

                            if (nextLink) {
                                link = nextLink;
                                observer.observe(document.querySelector('.post:last-of-type'))
                            } else {
                                observer.disconnect()
                            }
                        })
                    }
                }
            })
        } catch (error) {
            console.log(error)
        }
    }

    let observer = new IntersectionObserver(callback, options);

    observer.observe(document.querySelector('.post:last-of-type'))

}