package msfgui;

/**
 *
 * Represents a module rank. Immutable, like an integer.
 * @author scriptjunkie
 */
public final class Rank {
	//ManualRanking       = 0
	//LowRanking          = 100
	//AverageRanking      = 200
	//NormalRanking       = 300
	//GoodRanking         = 400
	//GreatRanking        = 500
	//ExcellentRanking    = 600
	private final int rank;

	//Creates from object, hopefully string or integer
	public Rank(Object rank){
		this(rank instanceof Integer ?
			((Integer)rank).intValue()
			: Integer.parseInt(rank.toString()));
	}

	//Only accept valid ranks
	public Rank(int rank){
		if(rank % 100 != 0 || rank < 0 || rank > 600)
			throw new RuntimeException("Invalid rank assigned in constructor.");
		this.rank = rank;
	}

	//Give back internal int; makes comparison easier
	public int toInt(){
		return rank;
	}

	//Return easy String representation
	public String toString(){
		switch(rank){
		case 0:
			return "Manual";
		case 100:
			return "Low";
		case 200:
			return "Average";
		case 300:
			return "Normal";
		case 400:
			return "Good";
		case 500:
			return "Great";
		case 600:
			return "Excellent";
		}
		throw new RuntimeException("Invalid internal rank state.");
	}

	//Static method to simplify getting rank string from int
	public static String toString(Object rank){
		return new Rank(rank).toString();
	}
}
